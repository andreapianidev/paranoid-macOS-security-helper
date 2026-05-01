//
//  PcapSYNScanOperation.swift
//  HelperDaemon
//
//  Port scanner via pcap/BPF che bypassa il firewall pf.
//  Costruisce frame Ethernet+IP+TCP SYN completi e li inietta via pcap_bridge_send_packet().
//  Cattura SYN-ACK/RST via pcap_bridge_next_packet() con filtro BPF.
//  Opera a Layer 2, sotto pf — funziona anche con VPN kill switch attivo.
//

import Foundation
import os

class PcapSYNScanOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    /// Risultato singola porta
    struct PortResult: Codable {
        let port: Int
        let state: String       // "open", "closed", "filtered"
        let latencyMs: Double?
    }

    /// Esegue il port scan via pcap (bypassa pf).
    /// - Parameters:
    ///   - targetIP: IP dell'host target
    ///   - ports: Porte da scansionare
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - gatewayMAC: MAC del gateway (necessario per costruire frame Ethernet)
    ///   - timeoutMs: Timeout per porta in millisecondi
    func execute(targetIP: String, ports: [Int32], interfaceName: String,
                 gatewayMAC: String, timeoutMs: Int32) -> Result<Data, Error> {

        // Ottieni MAC e IP dell'interfaccia locale
        guard let srcMAC = PacketBuilder.getInterfaceMAC(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere MAC di \(interfaceName)"))
        }
        guard let srcIPStr = PacketBuilder.getInterfaceIP(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere IP di \(interfaceName)"))
        }

        // Parsa gateway MAC
        let dstMAC = parseMAC(gatewayMAC)
        guard dstMAC.count == 6 else {
            return .failure(HelperError.invalidParameters("MAC gateway non valido: \(gatewayMAC)"))
        }

        let srcIP = PacketBuilder.ipToUInt32(srcIPStr)
        let dstIP = PacketBuilder.ipToUInt32(targetIP)

        guard srcIP > 0, dstIP > 0 else {
            return .failure(HelperError.invalidParameters("IP non validi: src=\(srcIPStr) dst=\(targetIP)"))
        }

        // Apri pcap con immediate mode per cattura real-time
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

        // Filtro BPF: cattura solo risposte TCP (SYN-ACK o RST) dall'IP target
        let bpfFilter = "tcp and src host \(targetIP) and dst host \(srcIPStr)"
        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            return .failure(HelperError.pcapError("Impossibile impostare filtro BPF TCP"))
        }

        var results: [PortResult] = []
        let resultsLock = NSLock()

        // Tracking SYN inviati per correlazione risposte
        struct PendingSYN {
            let srcPort: UInt16
            let dstPort: UInt16
            let seqNum: UInt32
            let sentTime: Date
        }
        var pendingSYNs: [UInt16: PendingSYN] = [:] // dstPort → PendingSYN
        let pendingLock = NSLock()

        // Scansione in batch: invia tutti i SYN, poi raccogli risposte
        // Più efficiente del per-porta perché pcap è serializzato sull'interfaccia
        let batchSize = min(ports.count, 100)

        for batchStart in stride(from: 0, to: ports.count, by: batchSize) {
            guard !isCancelled else { break }

            let batchEnd = min(batchStart + batchSize, ports.count)
            let batch = ports[batchStart..<batchEnd]

            // Invia SYN per ogni porta nel batch
            for port in batch {
                guard !isCancelled else { break }

                let srcPort = UInt16.random(in: 49152...65535)
                let seqNum = UInt32.random(in: 0...UInt32.max)

                var frame = [UInt8](repeating: 0, count: 74)
                var srcMACCopy = srcMAC
                var dstMACCopy = dstMAC
                let frameLen = build_eth_syn_frame(&frame, &srcMACCopy, &dstMACCopy,
                                                    srcIP, dstIP,
                                                    srcPort, UInt16(port), seqNum)

                pcap_bridge_send_packet(pcap, frame, Int32(frameLen))

                pendingLock.lock()
                pendingSYNs[UInt16(port)] = PendingSYN(
                    srcPort: srcPort, dstPort: UInt16(port),
                    seqNum: seqNum, sentTime: Date()
                )
                pendingLock.unlock()

                usleep(200) // 0.2ms tra pacchetti per non saturare
            }

            // Raccogli risposte per il batch
            let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)

            while Date() < deadline && !isCancelled {
                var packet = pcap_packet_t()
                let result = pcap_bridge_next_packet(pcap, &packet)

                if result == 1 && packet.length >= 54 {
                    // Parse Ethernet + IP + TCP dal frame catturato
                    let data = UnsafeBufferPointer(start: packet.data, count: Int(packet.length))

                    // Verifica EtherType IPv4 (0x0800)
                    guard data[12] == 0x08, data[13] == 0x00 else { continue }

                    // IP header a offset 14
                    let ipHeaderLen = Int(data[14] & 0x0F) * 4
                    guard packet.length >= 14 + ipHeaderLen + 20 else { continue }

                    // TCP header
                    let tcpOffset = 14 + ipHeaderLen
                    let respSrcPort = (UInt16(data[tcpOffset]) << 8) | UInt16(data[tcpOffset + 1])
                    let respDstPort = (UInt16(data[tcpOffset + 2]) << 8) | UInt16(data[tcpOffset + 3])
                    let flags = data[tcpOffset + 13]

                    // Verifica che corrisponda a un SYN pendente
                    pendingLock.lock()
                    guard let pending = pendingSYNs[respSrcPort],
                          respDstPort == pending.srcPort else {
                        pendingLock.unlock()
                        continue
                    }
                    pendingSYNs.removeValue(forKey: respSrcPort)
                    pendingLock.unlock()

                    let latency = Date().timeIntervalSince(pending.sentTime) * 1000.0

                    if (flags & UInt8(TCP_FLAG_SYN)) != 0 && (flags & UInt8(TCP_FLAG_ACK)) != 0 {
                        // SYN-ACK → porta aperta
                        resultsLock.lock()
                        results.append(PortResult(port: Int(respSrcPort), state: "open", latencyMs: latency))
                        resultsLock.unlock()

                        // Invia RST per chiudere connessione half-open
                        var rstFrame = [UInt8](repeating: 0, count: 54)
                        var rstSrcMAC = srcMAC
                        var rstDstMAC = dstMAC
                        let rstLen = build_eth_rst_frame(&rstFrame, &rstSrcMAC, &rstDstMAC,
                                                          srcIP, dstIP,
                                                          pending.srcPort, respSrcPort,
                                                          pending.seqNum + 1)
                        pcap_bridge_send_packet(pcap, rstFrame, Int32(rstLen))

                    } else if (flags & UInt8(TCP_FLAG_RST)) != 0 {
                        // RST → porta chiusa
                        resultsLock.lock()
                        results.append(PortResult(port: Int(respSrcPort), state: "closed", latencyMs: latency))
                        resultsLock.unlock()
                    }
                } else if result == -1 {
                    break
                }

                // Se tutte le risposte ricevute, esci dal loop
                pendingLock.lock()
                let remaining = pendingSYNs.count
                pendingLock.unlock()
                if remaining == 0 { break }
            }

            // Porte senza risposta → filtered
            pendingLock.lock()
            let timedOut = pendingSYNs
            pendingSYNs.removeAll()
            pendingLock.unlock()

            resultsLock.lock()
            for (port, _) in timedOut {
                if !results.contains(where: { $0.port == Int(port) }) {
                    results.append(PortResult(port: Int(port), state: "filtered", latencyMs: nil))
                }
            }
            resultsLock.unlock()
        }

        guard !isCancelled else {
            return .failure(HelperError.cancelled)
        }

        results.sort { $0.port < $1.port }

        do {
            let jsonData = try JSONEncoder().encode(results)
            let openCount = results.filter { $0.state == "open" }.count
            HelperLogger.operations.info("[PcapSYN] Scan completato: \(openCount) porte aperte su \(targetIP) (bypass pf)")
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione JSON fallita: \(error)"))
        }
    }

    // MARK: - ICMP Ping via pcap (bypassa pf)

    /// Risultato ICMP ping via pcap
    struct PcapPingResult: Codable {
        let latencyMs: Double?
        let ttl: Int?
        let received: Bool
    }

    /// Esegue ICMP ping via pcap/BPF (bypassa pf).
    func executePing(targetIP: String, interfaceName: String,
                     gatewayMAC: String, timeoutMs: Int32,
                     count: Int32 = 3) -> Result<Data, Error> {

        guard let srcMAC = PacketBuilder.getInterfaceMAC(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere MAC di \(interfaceName)"))
        }
        guard let srcIPStr = PacketBuilder.getInterfaceIP(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere IP di \(interfaceName)"))
        }

        let dstMAC = parseMAC(gatewayMAC)
        guard dstMAC.count == 6 else {
            return .failure(HelperError.invalidParameters("MAC gateway non valido: \(gatewayMAC)"))
        }

        let srcIP = PacketBuilder.ipToUInt32(srcIPStr)
        let dstIP = PacketBuilder.ipToUInt32(targetIP)

        guard srcIP > 0, dstIP > 0 else {
            return .failure(HelperError.invalidParameters("IP non validi"))
        }

        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 128, 1, Int32(min(timeoutMs, 100)), &errbuf)
        }
        guard let pcap = handle else {
            return .failure(HelperError.pcapError("pcap_open_live fallito"))
        }
        self.pcapHandle = pcap

        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        // Filtro BPF: solo ICMP Echo Reply dall'IP target
        let bpfFilter = "icmp[icmptype] = icmp-echoreply and src host \(targetIP)"
        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            return .failure(HelperError.pcapError("Impossibile impostare filtro BPF ICMP"))
        }

        let identifier = UInt16.random(in: 1...65535)
        var latencies: [Double] = []
        var ttlValue: Int?

        for seq in 0..<count {
            guard !isCancelled else { break }

            let sendTime = Date()

            var frame = [UInt8](repeating: 0, count: 74)
            var srcMACCopy = srcMAC
            var dstMACCopy = dstMAC
            let frameLen = build_eth_icmp_frame(&frame, &srcMACCopy, &dstMACCopy,
                                                 srcIP, dstIP,
                                                 identifier, UInt16(seq))
            pcap_bridge_send_packet(pcap, frame, Int32(frameLen))

            // Attendi risposta
            let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
            var received = false

            while Date() < deadline && !isCancelled {
                var packet = pcap_packet_t()
                let result = pcap_bridge_next_packet(pcap, &packet)

                if result == 1 && packet.length >= 42 {
                    let data = UnsafeBufferPointer(start: packet.data, count: Int(packet.length))

                    // Verifica EtherType IPv4
                    guard data[12] == 0x08, data[13] == 0x00 else { continue }

                    // IP header
                    let ipHeaderLen = Int(data[14] & 0x0F) * 4
                    guard packet.length >= 14 + ipHeaderLen + 8 else { continue }

                    // TTL dall'header IP
                    let frameTTL = Int(data[22])

                    // ICMP header a offset 14 + ipHeaderLen
                    let icmpOffset = 14 + ipHeaderLen
                    let icmpId = (UInt16(data[icmpOffset + 4]) << 8) | UInt16(data[icmpOffset + 5])

                    // Verifica che sia la nostra risposta
                    guard icmpId == identifier else { continue }

                    let latency = Date().timeIntervalSince(sendTime) * 1000.0
                    latencies.append(latency)
                    ttlValue = frameTTL
                    received = true
                    break
                } else if result == -1 {
                    break
                }
            }

            if !received && seq < count - 1 {
                usleep(100_000) // 100ms tra tentativi
            }
        }

        let avgLatency = latencies.isEmpty ? nil : latencies.reduce(0, +) / Double(latencies.count)

        let pingResult = PcapPingResult(
            latencyMs: avgLatency,
            ttl: ttlValue,
            received: !latencies.isEmpty
        )

        do {
            let jsonData = try JSONEncoder().encode(pingResult)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione fallita: \(error)"))
        }
    }

    // MARK: - Utility

    /// Parsa stringa MAC "AA:BB:CC:DD:EE:FF" in array [UInt8]
    private func parseMAC(_ mac: String) -> [UInt8] {
        let parts = mac.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        return parts
    }
}
