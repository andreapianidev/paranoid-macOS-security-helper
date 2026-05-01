//
//  SYNScanOperation.swift
//  HelperDaemon
//
//  Operazione SYN scan ibrida: raw socket per invio + pcap/BPF per ricezione.
//  Su macOS, SOCK_RAW + IPPROTO_TCP non riceve risposte TCP (il kernel le intercetta).
//  pcap/BPF opera a Layer 2 (BPF) e riceve copie di TUTTI i pacchetti, inclusi SYN-ACK/RST.
//  Ritorna [{port, state, latencyMs}] come JSON Data.
//

import Foundation
import os

class SYNScanOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    /// Risultato singola porta per serializzazione JSON
    struct PortScanResult: Codable {
        let port: Int
        let state: String       // "open", "closed", "filtered"
        let latencyMs: Double?
        let ttl: Int?           // TTL dall'header IP (solo IPv4, nil per filtered/IPv6)
    }

    /// Esegue il SYN scan sulle porte specificate (dual-stack IPv4/IPv6)
    func execute(targetIP: String, ports: [Int32], interfaceName: String,
                 timeoutMs: Int32, maxConcurrent: Int32) -> Result<Data, Error> {

        // Detect IPv4 vs IPv6
        if PacketBuilder.isIPv6(targetIP) {
            return executeIPv6(targetIP: targetIP, ports: ports, interfaceName: interfaceName,
                               timeoutMs: timeoutMs, maxConcurrent: maxConcurrent)
        } else {
            return executeIPv4(targetIP: targetIP, ports: ports, interfaceName: interfaceName,
                               timeoutMs: timeoutMs, maxConcurrent: maxConcurrent)
        }
    }

    // MARK: - IPv4 SYN Scan (full L2: pcap_inject send + pcap/BPF receive)
    //
    // Su macOS, raw socket IPPROTO_TCP NON funziona per SYN scan:
    // 1. sendto invia il SYN, ma il kernel TCP non conosce la connessione
    // 2. Quando arriva SYN-ACK, il kernel invia RST PRIMA che BPF lo consegni
    // 3. recv() su raw TCP socket non riceve mai nulla (kernel intercetta)
    //
    // Soluzione: operare interamente a Layer 2 via pcap/BPF:
    // - Invio: pcap_inject con frame Ethernet completo (bypassa kernel TCP)
    // - Ricezione: pcap_next_ex con filtro BPF (cattura a L2, prima del kernel)
    // - MAC target: risolto dalla tabella ARP di sistema (già popolata dal prepop)

    private func executeIPv4(targetIP: String, ports: [Int32], interfaceName: String,
                             timeoutMs: Int32, maxConcurrent: Int32) -> Result<Data, Error> {

        guard let srcIPStr = PacketBuilder.getInterfaceIP(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere IP di \(interfaceName)"))
        }

        let srcIP = PacketBuilder.ipToUInt32(srcIPStr)
        let dstIP = PacketBuilder.ipToUInt32(targetIP)

        guard srcIP > 0, dstIP > 0 else {
            return .failure(HelperError.invalidParameters("IP non validi: src=\(srcIPStr) dst=\(targetIP)"))
        }

        // Ottieni MAC sorgente (interfaccia locale)
        guard let srcMAC = PacketBuilder.getInterfaceMAC(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere MAC di \(interfaceName)"))
        }

        // Ottieni MAC destinazione dalla tabella ARP di sistema
        // (deve essere già stata popolata dal prepopulateARPTable dell'app)
        guard let dstMAC = resolveARPMac(for: targetIP) else {
            HelperLogger.forwardWarning(category: "Operations", message: "MAC non trovato per \(targetIP) — skip (ARP non popolato?)", tag: "[SYN]")
            // Ritorna tutte filtered — senza MAC L2 non possiamo inviare
            let filtered = ports.map { PortScanResult(port: Int($0), state: "filtered", latencyMs: nil, ttl: nil) }
            let jsonData = try? JSONEncoder().encode(filtered)
            return .success(jsonData ?? Data())
        }

        // Apri pcap per invio E ricezione (stesso handle, full L2)
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 128, 1, Int32(min(timeoutMs, 100)), &errbuf)
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("pcap_open_live fallito: \(errMsg)"))
        }
        self.pcapHandle = pcap
        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        // Filtro BPF: solo TCP da target verso noi (SYN-ACK o RST)
        let bpfFilter = "tcp and src host \(targetIP) and dst host \(srcIPStr)"
        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            return .failure(HelperError.pcapError("Impossibile impostare filtro BPF: tcp src=\(targetIP) dst=\(srcIPStr)"))
        }

        // Tracking SYN pendenti: dstPort → probe info
        struct PendingSYN {
            let srcPort: UInt16
            let dstPort: UInt16
            let seqNum: UInt32
            let sentTime: Date
        }
        var pendingSYNs: [UInt16: PendingSYN] = [:] // keyed by dstPort (remote port)
        var results: [PortScanResult] = []
        var resolvedPorts = Set<Int>()

        // Fase 1: Invia tutti i SYN via pcap_inject (L2, bypassa kernel TCP + pf)
        for port in ports {
            guard !isCancelled else { break }

            let srcPort = UInt16.random(in: 49152...65535)
            let seqNum = UInt32.random(in: 0...UInt32.max)

            var frame = [UInt8](repeating: 0, count: 74) // ETH(14) + IP(20) + TCP(40 con opzioni)
            var srcMACCopy = srcMAC
            var dstMACCopy = dstMAC
            let frameLen = build_eth_syn_frame(&frame, &srcMACCopy, &dstMACCopy,
                                                srcIP, dstIP,
                                                srcPort, UInt16(port), seqNum)

            let sendResult = pcap_bridge_send_packet(pcap, frame, Int32(frameLen))

            if sendResult == 0 {
                pendingSYNs[UInt16(port)] = PendingSYN(
                    srcPort: srcPort, dstPort: UInt16(port),
                    seqNum: seqNum, sentTime: Date()
                )
            } else {
                results.append(PortScanResult(port: Int(port), state: "filtered", latencyMs: nil, ttl: nil))
            }

            usleep(200) // 0.2ms tra pacchetti per non saturare
        }

        // Fase 2: Cattura risposte via pcap/BPF
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)

        while Date() < deadline && !pendingSYNs.isEmpty && !isCancelled {
            var pkt = pcap_packet_t()
            let rc = pcap_bridge_next_packet(pcap, &pkt)

            if rc == 1 && pkt.length >= 54, let data = pkt.data {
                // Parse frame Ethernet (14 byte) + IP + TCP
                guard data[12] == 0x08, data[13] == 0x00 else { continue }

                let ipHeaderLen = Int(data[14] & 0x0F) * 4
                let tcpOffset = 14 + ipHeaderLen
                guard pkt.length >= Int32(tcpOffset + 20) else { continue }

                let respSrcPort = (UInt16(data[tcpOffset]) << 8) | UInt16(data[tcpOffset + 1])
                let respDstPort = (UInt16(data[tcpOffset + 2]) << 8) | UInt16(data[tcpOffset + 3])
                let flags = data[tcpOffset + 13]

                // TTL dall'header IP: byte 8 dopo inizio IP (offset 14 + 8 = 22)
                let responseTTL = Int(data[14 + 8])

                // Correla: respSrcPort = porta remota, respDstPort = nostro srcPort
                guard let pending = pendingSYNs[respSrcPort],
                      respDstPort == pending.srcPort else { continue }

                let latency = Date().timeIntervalSince(pending.sentTime) * 1000.0

                if (flags & UInt8(TCP_FLAG_SYN)) != 0 && (flags & UInt8(TCP_FLAG_ACK)) != 0 {
                    // SYN-ACK → porta aperta
                    results.append(PortScanResult(port: Int(respSrcPort), state: "open", latencyMs: latency, ttl: responseTTL))
                    resolvedPorts.insert(Int(respSrcPort))
                    pendingSYNs.removeValue(forKey: respSrcPort)

                    // Invia RST per chiudere connessione half-open (via pcap_inject L2)
                    var rstFrame = [UInt8](repeating: 0, count: 54) // ETH(14) + IP(20) + TCP(20)
                    var rstSrcMAC = srcMAC
                    var rstDstMAC = dstMAC
                    let rstLen = build_eth_rst_frame(&rstFrame, &rstSrcMAC, &rstDstMAC,
                                                      srcIP, dstIP,
                                                      pending.srcPort, respSrcPort,
                                                      pending.seqNum + 1)
                    pcap_bridge_send_packet(pcap, rstFrame, Int32(rstLen))

                } else if (flags & UInt8(TCP_FLAG_RST)) != 0 {
                    // RST → porta chiusa (TTL utile per OS fingerprint anche su porte chiuse)
                    results.append(PortScanResult(port: Int(respSrcPort), state: "closed", latencyMs: latency, ttl: responseTTL))
                    resolvedPorts.insert(Int(respSrcPort))
                    pendingSYNs.removeValue(forKey: respSrcPort)
                }
            } else if rc == -1 {
                break
            }
        }

        // Fase 3: Porte senza risposta → filtered
        for (port, _) in pendingSYNs {
            if !resolvedPorts.contains(Int(port)) {
                results.append(PortScanResult(port: Int(port), state: "filtered", latencyMs: nil, ttl: nil))
            }
        }

        guard !isCancelled else {
            return .failure(HelperError.cancelled)
        }

        results.sort { $0.port < $1.port }

        do {
            let jsonData = try JSONEncoder().encode(results)
            let openCount = results.filter { $0.state == "open" }.count
            let closedCount = results.filter { $0.state == "closed" }.count
            HelperLogger.operations.info("[SYN] Scan IPv4 L2 completato: \(openCount) open, \(closedCount) closed su \(targetIP)")
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione JSON fallita: \(error)"))
        }
    }

    // MARK: - ARP MAC Resolution

    /// Risolve il MAC address di un IP dalla tabella ARP di sistema via `arp -n`.
    /// Prerequisito: ARP prepopulation deve essere già stata eseguita dall'app.
    private func resolveARPMac(for ip: String) -> [UInt8]? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
        process.arguments = ["-n", ip]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return nil }

        // Formato: "? (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
        // Oppure: "? (192.168.0.1) at (incomplete) on en0 ifscope [ethernet]"
        guard let atRange = output.range(of: " at ") else { return nil }
        let afterAt = output[atRange.upperBound...]
        guard let spaceAfterMAC = afterAt.firstIndex(of: " ") else { return nil }
        let macStr = String(afterAt[..<spaceAfterMAC])
        guard macStr != "(incomplete)" else { return nil }

        let parts = macStr.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        guard parts.count == 6 else { return nil }
        return parts
    }

    // MARK: - IPv6 SYN Scan

    /// SYN scan IPv6: payload-only (no IP header), kernel genera header IPv6,
    /// bind() per source address control, recv() ha TCP a offset 0.
    private func executeIPv6(targetIP: String, ports: [Int32], interfaceName: String,
                             timeoutMs: Int32, maxConcurrent: Int32) -> Result<Data, Error> {

        // Determina indirizzo IPv6 sorgente dall'interfaccia
        let isLinkLocal = PacketBuilder.isIPv6LinkLocal(targetIP)
        guard let srcIPv6Str = PacketBuilder.getInterfaceIPv6(interfaceName, preferGlobal: !isLinkLocal) else {
            return .failure(HelperError.operationFailed("Nessun IPv6 su \(interfaceName)"))
        }

        guard var srcAddr = PacketBuilder.parseIPv6(srcIPv6Str),
              var dstAddr = PacketBuilder.parseIPv6(targetIP) else {
            return .failure(HelperError.invalidParameters("IPv6 non validi: src=\(srcIPv6Str) dst=\(targetIP)"))
        }

        let scopeId = PacketBuilder.scopeID(interfaceName)

        // Crea raw socket TCP IPv6 per invio SYN (condiviso — sendto è thread-safe)
        let sendSock = PacketBuilder.createRawSocketV6(protocol: Int32(IPPROTO_TCP))
        guard sendSock >= 0 else {
            return .failure(HelperError.socketError("Impossibile creare raw socket TCP IPv6: errno=\(errno)"))
        }

        // Bind a source address per controllare IPv6 src nel header generato dal kernel
        guard PacketBuilder.bindRawSocketV6(sendSock, interface: interfaceName, srcAddr: srcAddr) else {
            raw_socket_close(sendSock)
            return .failure(HelperError.socketError("Bind IPv6 fallito su \(interfaceName): errno=\(errno)"))
        }

        defer {
            raw_socket_close(sendSock)
        }

        var results: [PortScanResult] = []
        let resultsLock = NSLock()

        let semaphore = DispatchSemaphore(value: Int(maxConcurrent))
        let group = DispatchGroup()

        for port in ports {
            guard !isCancelled else { break }

            semaphore.wait()
            group.enter()

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                defer {
                    semaphore.signal()
                    group.leave()
                }

                guard self?.isCancelled != true else { return }

                // Ogni thread ha il proprio recvSock
                let recvSock = PacketBuilder.createRawSocketV6(protocol: Int32(IPPROTO_TCP))
                guard recvSock >= 0 else {
                    resultsLock.lock()
                    results.append(PortScanResult(port: Int(port), state: "filtered", latencyMs: nil, ttl: nil))
                    resultsLock.unlock()
                    return
                }
                raw_socket_set_recv_timeout(recvSock, timeoutMs)
                defer { raw_socket_close(recvSock) }

                let srcPort = UInt16.random(in: 49152...65535)
                let seqNum = UInt32.random(in: 0...UInt32.max)
                let startTime = Date()

                // Costruisci TCP SYN payload (SENZA header IPv6 — kernel lo aggiunge)
                var synPayload = PacketBuilder.buildTCPSYNPayload(
                    srcPort: srcPort, dstPort: UInt16(port), seqNum: seqNum
                )

                // Calcola e patcha TCP checksum con pseudo-header IPv6
                let cksum = PacketBuilder.computeTCP6Checksum(
                    srcIPv6: srcAddr, dstIPv6: dstAddr, tcpSegment: synPayload
                )
                PacketBuilder.patchTCPChecksum(&synPayload, checksum: cksum)

                // Costruisci sockaddr_in6 destinazione
                var destAddr6 = sockaddr_in6()
                destAddr6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                destAddr6.sin6_family = sa_family_t(AF_INET6)
                destAddr6.sin6_addr = dstAddr
                destAddr6.sin6_scope_id = isLinkLocal ? scopeId : 0

                // Invia payload TCP puro (kernel aggiunge header IPv6)
                let sent = synPayload.withUnsafeBytes { buf in
                    withUnsafePointer(to: &destAddr6) { addr in
                        addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                            sendto(sendSock, buf.baseAddress, buf.count, 0, sa,
                                   socklen_t(MemoryLayout<sockaddr_in6>.size))
                        }
                    }
                }

                guard sent > 0 else {
                    resultsLock.lock()
                    results.append(PortScanResult(port: Int(port), state: "filtered", latencyMs: nil, ttl: nil))
                    resultsLock.unlock()
                    return
                }

                // Attendi risposta: su IPv6 recv() NON include IPv6 header.
                // TCP header inizia a OFFSET 0 nel buffer.
                var recvBuf = [UInt8](repeating: 0, count: 256)
                let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)

                while Date() < deadline {
                    let n = recv(recvSock, &recvBuf, recvBuf.count, 0)
                    guard n >= 20 else {
                        if errno == EAGAIN || errno == EWOULDBLOCK {
                            break
                        }
                        continue
                    }

                    // IPv6: TCP header a offset 0 (no IPv6 header nel buffer)
                    let respSrcPort = (UInt16(recvBuf[0]) << 8) | UInt16(recvBuf[1])
                    let respDstPort = (UInt16(recvBuf[2]) << 8) | UInt16(recvBuf[3])

                    guard respSrcPort == UInt16(port), respDstPort == srcPort else { continue }

                    let flags = recvBuf[13]
                    let latency = Date().timeIntervalSince(startTime) * 1000.0

                    if (flags & UInt8(TCP_FLAG_SYN)) != 0 && (flags & UInt8(TCP_FLAG_ACK)) != 0 {
                        resultsLock.lock()
                        results.append(PortScanResult(port: Int(port), state: "open", latencyMs: latency, ttl: nil))
                        resultsLock.unlock()

                        self?.sendRSTv6(sendSock: sendSock, srcAddr: srcAddr, dstAddr: dstAddr,
                                        srcPort: srcPort, dstPort: UInt16(port),
                                        seqNum: seqNum + 1, scopeId: isLinkLocal ? scopeId : 0)
                        return
                    } else if (flags & UInt8(TCP_FLAG_RST)) != 0 {
                        resultsLock.lock()
                        results.append(PortScanResult(port: Int(port), state: "closed", latencyMs: latency, ttl: nil))
                        resultsLock.unlock()
                        return
                    }
                }

                resultsLock.lock()
                results.append(PortScanResult(port: Int(port), state: "filtered", latencyMs: nil, ttl: nil))
                resultsLock.unlock()
            }
        }

        group.wait()

        guard !isCancelled else {
            return .failure(HelperError.cancelled)
        }

        results.sort { $0.port < $1.port }

        do {
            let jsonData = try JSONEncoder().encode(results)
            HelperLogger.operations.info("[SYN] Scan IPv6 completato: \(results.filter { $0.state == "open" }.count) porte aperte su \(targetIP)")
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione JSON fallita: \(error)"))
        }
    }

    /// Invia un RST per chiudere una connessione half-open
    private func sendRST(sendSock: Int32, srcIP: UInt32, dstIP: UInt32,
                         srcPort: UInt16, dstPort: UInt16, seqNum: UInt32) {
        // Costruisci pacchetto RST minimale
        var packet = [UInt8](repeating: 0, count: 40)

        // Header IP
        packet[0] = 0x45
        let totalLen = UInt16(40)
        packet[2] = UInt8(totalLen >> 8)
        packet[3] = UInt8(totalLen & 0xFF)
        packet[5] = UInt8(arc4random() & 0xFF)
        packet[6] = 0x40 // Don't Fragment
        packet[8] = 64   // TTL
        packet[9] = UInt8(IPPROTO_TCP)
        // src/dst IP in network byte order
        let srcNet = CFSwapInt32HostToBig(srcIP)
        let dstNet = CFSwapInt32HostToBig(dstIP)
        withUnsafeBytes(of: srcNet) { buf in
            packet[12] = buf[0]; packet[13] = buf[1]; packet[14] = buf[2]; packet[15] = buf[3]
        }
        withUnsafeBytes(of: dstNet) { buf in
            packet[16] = buf[0]; packet[17] = buf[1]; packet[18] = buf[2]; packet[19] = buf[3]
        }

        // Header TCP
        packet[20] = UInt8(srcPort >> 8)
        packet[21] = UInt8(srcPort & 0xFF)
        packet[22] = UInt8(dstPort >> 8)
        packet[23] = UInt8(dstPort & 0xFF)
        // seq number
        let seqNet = CFSwapInt32HostToBig(seqNum)
        withUnsafeBytes(of: seqNet) { buf in
            packet[24] = buf[0]; packet[25] = buf[1]; packet[26] = buf[2]; packet[27] = buf[3]
        }
        packet[32] = 0x50  // data offset = 5 (20 byte)
        packet[33] = UInt8(TCP_FLAG_RST | TCP_FLAG_ACK)
        packet[34] = 0x00  // window = 0
        packet[35] = 0x00

        // Checksum IP
        let ipCksum = ip_checksum(&packet, 20)
        withUnsafeBytes(of: ipCksum) { buf in
            packet[10] = buf[0]; packet[11] = buf[1]
        }

        var destAddr = sockaddr_in()
        destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destAddr.sin_family = sa_family_t(AF_INET)
        destAddr.sin_addr.s_addr = CFSwapInt32HostToBig(dstIP)

        withUnsafePointer(to: &destAddr) { addr in
            addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                sendto(sendSock, &packet, 40, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    /// Invia un RST IPv6 per chiudere una connessione half-open
    private func sendRSTv6(sendSock: Int32, srcAddr: in6_addr, dstAddr: in6_addr,
                           srcPort: UInt16, dstPort: UInt16, seqNum: UInt32,
                           scopeId: UInt32) {
        // Costruisci TCP RST payload (SENZA header IPv6)
        var rstPayload = PacketBuilder.buildTCPRSTPayload(
            srcPort: srcPort, dstPort: dstPort, seqNum: seqNum
        )

        // Calcola e patcha TCP checksum con pseudo-header IPv6
        let cksum = PacketBuilder.computeTCP6Checksum(
            srcIPv6: srcAddr, dstIPv6: dstAddr, tcpSegment: rstPayload
        )
        PacketBuilder.patchTCPChecksum(&rstPayload, checksum: cksum)

        var destAddr6 = sockaddr_in6()
        destAddr6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        destAddr6.sin6_family = sa_family_t(AF_INET6)
        destAddr6.sin6_addr = dstAddr
        destAddr6.sin6_scope_id = scopeId

        rstPayload.withUnsafeBytes { buf in
            withUnsafePointer(to: &destAddr6) { addr in
                addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    _ = sendto(sendSock, buf.baseAddress, buf.count, 0, sa,
                               socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }
    }

    // MARK: - SYN-ACK Capture per TCP Fingerprinting

    /// Risultato cattura SYN-ACK per fingerprinting
    struct SYNACKResult: Codable {
        let windowSize: Int
        let mss: Int
        let sackPermitted: Bool
        let timestampEnabled: Bool
        let windowScaling: Int
        let ttl: Int
        let timestampValue: UInt32    // TSval per clock skew fingerprinting
        let optionsOrder: [UInt8]     // Ordine opzioni TCP (fingerprint OS)
    }

    /// Cattura un SYN-ACK per analisi TCP fingerprint (full L2: pcap_inject send + pcap receive)
    func captureSYNACK(targetIP: String, port: Int32, interfaceName: String,
                       timeoutMs: Int32) -> Result<Data, Error> {

        guard let srcIPStr = PacketBuilder.getInterfaceIP(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere IP di \(interfaceName)"))
        }

        let srcIP = PacketBuilder.ipToUInt32(srcIPStr)
        let dstIP = PacketBuilder.ipToUInt32(targetIP)

        guard let srcMAC = PacketBuilder.getInterfaceMAC(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere MAC di \(interfaceName)"))
        }

        guard let dstMAC = resolveARPMac(for: targetIP) else {
            return .failure(HelperError.operationFailed("MAC non trovato per \(targetIP) — ARP non popolato?"))
        }

        // pcap per invio SYN E ricezione SYN-ACK (snaplen 512 per opzioni TCP)
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 512, 1, Int32(min(timeoutMs, 100)), &errbuf)
        }
        guard let pcap = handle else {
            return .failure(HelperError.pcapError("pcap_open_live fallito per SYN-ACK capture"))
        }
        self.pcapHandle = pcap
        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        let bpfFilter = "tcp and src host \(targetIP) and src port \(port) and dst host \(srcIPStr)"
        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            return .failure(HelperError.pcapError("Impossibile impostare filtro BPF per SYN-ACK"))
        }

        let srcPort = UInt16.random(in: 49152...65535)
        let seqNum = UInt32.random(in: 0...UInt32.max)

        // Invia SYN via pcap_inject (L2)
        var frame = [UInt8](repeating: 0, count: 74)
        var srcMACCopy = srcMAC
        var dstMACCopy = dstMAC
        let frameLen = build_eth_syn_frame(&frame, &srcMACCopy, &dstMACCopy,
                                            srcIP, dstIP,
                                            srcPort, UInt16(port), seqNum)

        guard pcap_bridge_send_packet(pcap, frame, Int32(frameLen)) == 0 else {
            return .failure(HelperError.socketError("pcap_inject fallito per SYN-ACK capture"))
        }

        // Attendi SYN-ACK via pcap e analizza opzioni TCP
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)

        while Date() < deadline && !isCancelled {
            var pkt = pcap_packet_t()
            let rc = pcap_bridge_next_packet(pcap, &pkt)

            guard rc == 1, pkt.length >= 54, let data = pkt.data else {
                if rc == -1 { break }
                continue
            }

            guard data[12] == 0x08, data[13] == 0x00 else { continue }

            let ipHeaderLen = Int(data[14] & 0x0F) * 4
            let tcpOffset = 14 + ipHeaderLen
            guard pkt.length >= Int32(tcpOffset + 20) else { continue }

            let respSrcPort = (UInt16(data[tcpOffset]) << 8) | UInt16(data[tcpOffset + 1])
            let respDstPort = (UInt16(data[tcpOffset + 2]) << 8) | UInt16(data[tcpOffset + 3])

            guard respSrcPort == UInt16(port), respDstPort == srcPort else { continue }

            let flags = data[tcpOffset + 13]
            guard (flags & UInt8(TCP_FLAG_SYN)) != 0,
                  (flags & UInt8(TCP_FLAG_ACK)) != 0 else { continue }

            // Parse TCP options dal frame pcap
            let tcpLen = Int(pkt.length) - tcpOffset
            var synackResult = synack_result_t()

            var tcpBuf = [UInt8](repeating: 0, count: tcpLen)
            for i in 0..<tcpLen { tcpBuf[i] = data[tcpOffset + i] }

            tcpBuf.withUnsafeMutableBufferPointer { buf in
                buf.baseAddress!.withMemoryRebound(to: tcp_header_t.self, capacity: 1) { tcp in
                    parse_tcp_options(tcp, Int32(tcpLen), &synackResult)
                }
            }

            let ttl = data[14 + 8]

            // Invia RST via pcap_inject (L2)
            var rstFrame = [UInt8](repeating: 0, count: 54)
            var rstSrcMAC = srcMAC
            var rstDstMAC = dstMAC
            let rstLen = build_eth_rst_frame(&rstFrame, &rstSrcMAC, &rstDstMAC,
                                              srcIP, dstIP,
                                              srcPort, UInt16(port),
                                              seqNum + 1)
            pcap_bridge_send_packet(pcap, rstFrame, Int32(rstLen))

            // Estrai ordine opzioni TCP (C fixed-size array → Swift tuple, serve withUnsafePointer)
            let orderCount = min(Int(synackResult.options_order_count), 12)
            let optionsOrder: [UInt8] = withUnsafePointer(to: synackResult.options_order) { ptr in
                ptr.withMemoryRebound(to: UInt8.self, capacity: 12) { buf in
                    (0..<orderCount).map { buf[$0] }
                }
            }

            let result = SYNACKResult(
                windowSize: Int(synackResult.window_size),
                mss: Int(synackResult.mss),
                sackPermitted: synackResult.sack_permitted != 0,
                timestampEnabled: synackResult.timestamp_enabled != 0,
                windowScaling: Int(synackResult.window_scaling),
                ttl: Int(ttl),
                timestampValue: synackResult.timestamp_value,
                optionsOrder: optionsOrder
            )

            do {
                let jsonData = try JSONEncoder().encode(result)
                return .success(jsonData)
            } catch {
                return .failure(HelperError.operationFailed("Serializzazione fallita: \(error)"))
            }
        }

        return .failure(HelperError.operationFailed("Nessun SYN-ACK ricevuto da \(targetIP):\(port)"))
    }
}
