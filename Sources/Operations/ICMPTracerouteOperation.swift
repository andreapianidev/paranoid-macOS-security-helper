//
//  ICMPTracerouteOperation.swift
//  HelperDaemon
//
//  Operazione traceroute ICMP raw con incremento TTL progressivo.
//  Per ogni hop: invia ICMP Echo Request con TTL crescente,
//  cattura ICMP Time Exceeded (type 11) o Echo Reply (type 0).
//  Molto più veloce e preciso del Process-based `/usr/sbin/traceroute`.
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//

import Foundation
import os

class ICMPTracerouteOperation: BaseOperation {

    override func cancel() {
        super.cancel()
    }

    // MARK: - Risultato

    struct TracerouteHopResult: Codable {
        let hop: Int
        let ip: String?
        let latencyMs: Double?
        let timedOut: Bool
    }

    // MARK: - Esecuzione

    /// Esegue traceroute ICMP raw con TTL/hop limit incrementale (dual-stack IPv4/IPv6).
    func execute(targetIP: String, maxHops: Int32, timeoutMs: Int32,
                 count: Int32, interfaceName: String) -> Result<Data, Error> {

        if PacketBuilder.isIPv6(targetIP) {
            return executeIPv6(targetIP: targetIP, maxHops: maxHops, timeoutMs: timeoutMs,
                               count: count, interfaceName: interfaceName)
        } else {
            return executeIPv4(targetIP: targetIP, maxHops: maxHops, timeoutMs: timeoutMs,
                               count: count, interfaceName: interfaceName)
        }
    }

    // MARK: - IPv4

    private func executeIPv4(targetIP: String, maxHops: Int32, timeoutMs: Int32,
                             count: Int32, interfaceName: String) -> Result<Data, Error> {

        guard let srcIPStr = PacketBuilder.getInterfaceIP(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere IP di \(interfaceName)"))
        }

        let srcIP = PacketBuilder.ipToUInt32(srcIPStr)
        let dstIP = PacketBuilder.ipToUInt32(targetIP)

        guard srcIP > 0, dstIP > 0 else {
            return .failure(HelperError.invalidParameters("IP non validi: src=\(srcIPStr) dst=\(targetIP)"))
        }

        // Crea raw socket ICMP
        let sockfd = raw_socket_create(Int32(IPPROTO_ICMP))
        guard sockfd >= 0 else {
            return .failure(HelperError.socketError("Impossibile creare raw socket ICMP: errno=\(errno)"))
        }
        raw_socket_set_hdrincl(sockfd)

        // Timeout per singolo probe
        let probeTimeout = max(timeoutMs, 500)
        raw_socket_set_recv_timeout(sockfd, probeTimeout)

        defer { raw_socket_close(sockfd) }

        let identifier = UInt16(getpid() & 0xFFFF)
        var hops: [TracerouteHopResult] = []
        var sequence: UInt16 = 0
        var reachedTarget = false

        HelperLogger.operations.info("[Traceroute] Traceroute ICMP avviato verso \(targetIP), maxHops=\(maxHops), probes/hop=\(count)")

        for ttl in 1...maxHops {
            guard !isCancelled else {
                return .failure(HelperError.cancelled)
            }

            var hopIP: String?
            var bestLatency: Double?
            var allTimedOut = true

            for probe in 0..<count {
                guard !isCancelled else {
                    return .failure(HelperError.cancelled)
                }

                sequence &+= 1
                let sendTime = Date()

                // Costruisci ICMP Echo Request con TTL personalizzato
                var packet = [UInt8](repeating: 0, count: 64)
                let length = build_icmp_echo_packet(&packet, srcIP, dstIP, identifier, sequence)

                // Patch del TTL nell'header IP (byte offset 8)
                packet[8] = UInt8(ttl)

                // Ricalcola checksum IP dopo modifica TTL
                // Azzera checksum IP (offset 10-11), poi ricalcola
                packet[10] = 0
                packet[11] = 0
                let ipChksum = packet.withUnsafeBufferPointer { buf in
                    ip_checksum(buf.baseAddress, 20)
                }
                packet[10] = UInt8(ipChksum & 0xFF)
                packet[11] = UInt8((ipChksum >> 8) & 0xFF)

                // Invia il pacchetto
                var destAddr = sockaddr_in()
                destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                destAddr.sin_family = sa_family_t(AF_INET)
                destAddr.sin_addr.s_addr = CFSwapInt32HostToBig(dstIP)

                let sentBytes = packet.prefix(Int(length)).withUnsafeBytes { buf in
                    withUnsafePointer(to: &destAddr) { addr in
                        addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                            sendto(sockfd, buf.baseAddress, buf.count, 0, sa,
                                   socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                }

                guard sentBytes > 0 else { continue }

                // Attendi risposta: ICMP Time Exceeded (type 11) o Echo Reply (type 0)
                let deadline = sendTime.addingTimeInterval(Double(probeTimeout) / 1000.0)

                while Date() < deadline {
                    var recvBuf = [UInt8](repeating: 0, count: 512)
                    let n = recv(sockfd, &recvBuf, recvBuf.count, 0)

                    guard n > 0 else {
                        if errno == EAGAIN || errno == EWOULDBLOCK { break }
                        continue
                    }

                    // Parse header IP della risposta
                    let ipHeaderLen = Int(recvBuf[0] & 0x0F) * 4
                    guard ipHeaderLen >= 20, n >= ipHeaderLen + 8 else { continue }

                    let icmpType = recvBuf[ipHeaderLen]

                    // IP sorgente della risposta (chi ha risposto)
                    let respIP = "\(recvBuf[12]).\(recvBuf[13]).\(recvBuf[14]).\(recvBuf[15])"

                    if icmpType == 11 {
                        // ICMP Time Exceeded — router intermedio
                        let innerOffset = ipHeaderLen + 8
                        let rawInnerIPLen = n >= innerOffset + 1 ? Int(recvBuf[innerOffset] & 0x0F) * 4 : 20
                        let innerIPLen = rawInnerIPLen >= 20 ? rawInnerIPLen : 20
                        let innerICMPOffset = innerOffset + innerIPLen

                        guard n >= innerICMPOffset + 8 else { continue }

                        let origId = (UInt16(recvBuf[innerICMPOffset + 4]) << 8) | UInt16(recvBuf[innerICMPOffset + 5])
                        let origSeq = (UInt16(recvBuf[innerICMPOffset + 6]) << 8) | UInt16(recvBuf[innerICMPOffset + 7])

                        guard origId == identifier, origSeq == sequence else { continue }

                        let latency = Date().timeIntervalSince(sendTime) * 1000.0
                        hopIP = respIP
                        if bestLatency == nil || latency < bestLatency! {
                            bestLatency = latency
                        }
                        allTimedOut = false
                        break

                    } else if icmpType == 0 {
                        // ICMP Echo Reply — target raggiunto
                        let respId = (UInt16(recvBuf[ipHeaderLen + 4]) << 8) | UInt16(recvBuf[ipHeaderLen + 5])
                        let respSeq = (UInt16(recvBuf[ipHeaderLen + 6]) << 8) | UInt16(recvBuf[ipHeaderLen + 7])

                        guard respId == identifier, respSeq == sequence else { continue }

                        let latency = Date().timeIntervalSince(sendTime) * 1000.0
                        hopIP = respIP
                        if bestLatency == nil || latency < bestLatency! {
                            bestLatency = latency
                        }
                        allTimedOut = false
                        reachedTarget = true
                        break
                    }
                }

                if probe < count - 1 {
                    usleep(50_000) // 50ms
                }
            }

            hops.append(TracerouteHopResult(hop: Int(ttl), ip: hopIP, latencyMs: bestLatency, timedOut: allTimedOut))

            if reachedTarget { break }
        }

        return encodeResults(hops: hops, targetIP: targetIP, reachedTarget: reachedTarget)
    }

    // MARK: - IPv6

    /// Traceroute IPv6: usa IPV6_UNICAST_HOPS per settare hop limit progressivamente.
    /// ICMPv6 Time Exceeded = type 3 (non 11 come ICMPv4).
    /// ICMPv6 Echo Reply = type 129.
    /// recv() non include IPv6 header — ICMPv6 a offset 0.
    /// Hop limit e indirizzo sorgente via recvmsg() ancillary data.
    private func executeIPv6(targetIP: String, maxHops: Int32, timeoutMs: Int32,
                             count: Int32, interfaceName: String) -> Result<Data, Error> {

        let isLinkLocal = PacketBuilder.isIPv6LinkLocal(targetIP)
        guard let srcIPv6Str = PacketBuilder.getInterfaceIPv6(interfaceName, preferGlobal: !isLinkLocal) else {
            return .failure(HelperError.operationFailed("Nessun IPv6 su \(interfaceName)"))
        }

        guard let srcAddr = PacketBuilder.parseIPv6(srcIPv6Str),
              var dstAddr = PacketBuilder.parseIPv6(targetIP) else {
            return .failure(HelperError.invalidParameters("IPv6 non validi"))
        }

        let scopeId = PacketBuilder.scopeID(interfaceName)

        // Crea raw socket ICMPv6
        let sockfd = PacketBuilder.createRawSocketV6(protocol: Int32(IPPROTO_ICMPV6))
        guard sockfd >= 0 else {
            return .failure(HelperError.socketError("Impossibile creare raw socket ICMPv6: errno=\(errno)"))
        }

        guard PacketBuilder.bindRawSocketV6(sockfd, interface: interfaceName, srcAddr: srcAddr) else {
            raw_socket_close(sockfd)
            return .failure(HelperError.socketError("Bind ICMPv6 fallito: errno=\(errno)"))
        }

        let probeTimeout = max(timeoutMs, 500)
        raw_socket_set_recv_timeout(sockfd, probeTimeout)

        defer { raw_socket_close(sockfd) }

        let identifier = UInt16(getpid() & 0xFFFF)
        var hops: [TracerouteHopResult] = []
        var sequence: UInt16 = 0
        var reachedTarget = false

        HelperLogger.operations.info("[Traceroute] Traceroute ICMPv6 avviato verso \(targetIP), maxHops=\(maxHops)")

        for hopLimit in 1...maxHops {
            guard !isCancelled else {
                return .failure(HelperError.cancelled)
            }

            // Setta hop limit per questo hop via setsockopt (equivalente TTL per IPv6)
            var hl = Int32(hopLimit)
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hl, socklen_t(MemoryLayout<Int32>.size))

            var hopIP: String?
            var bestLatency: Double?
            var allTimedOut = true

            for probe in 0..<count {
                guard !isCancelled else {
                    return .failure(HelperError.cancelled)
                }

                sequence &+= 1
                let sendTime = Date()

                // Costruisci ICMPv6 Echo Request (checksum=0, kernel lo calcola)
                let payload = PacketBuilder.buildICMPv6EchoPayload(
                    identifier: identifier, sequence: sequence
                )

                var destAddr6 = sockaddr_in6()
                destAddr6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                destAddr6.sin6_family = sa_family_t(AF_INET6)
                destAddr6.sin6_addr = dstAddr
                destAddr6.sin6_scope_id = isLinkLocal ? scopeId : 0

                let sentBytes = payload.withUnsafeBytes { buf in
                    withUnsafePointer(to: &destAddr6) { addr in
                        addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                            sendto(sockfd, buf.baseAddress, buf.count, 0, sa,
                                   socklen_t(MemoryLayout<sockaddr_in6>.size))
                        }
                    }
                }

                guard sentBytes > 0 else { continue }

                // Attendi ICMPv6: Time Exceeded (type 3) o Echo Reply (type 129)
                let deadline = sendTime.addingTimeInterval(Double(probeTimeout) / 1000.0)

                while Date() < deadline {
                    guard let result = PacketBuilder.recvmsgV6(sockfd, bufferSize: 512) else {
                        if errno == EAGAIN || errno == EWOULDBLOCK { break }
                        continue
                    }

                    guard result.count >= 8 else { continue }

                    // ICMPv6 a offset 0 (no IPv6 header nel buffer)
                    let icmpType = result.data[0]

                    if icmpType == 3 {
                        // ICMPv6 Time Exceeded — router intermedio
                        // Payload: 4 byte unused + original IPv6 header (40B) + original ICMPv6 (8B min)
                        // Inner ICMPv6 identifier/sequence a offset 4+40+4 = 48 e 4+40+6 = 50
                        let innerICMPOffset = 4 + 40  // unused(4) + IPv6 header(40)
                        guard result.count >= innerICMPOffset + 8 else { continue }

                        let origId = (UInt16(result.data[innerICMPOffset + 4]) << 8) | UInt16(result.data[innerICMPOffset + 5])
                        let origSeq = (UInt16(result.data[innerICMPOffset + 6]) << 8) | UInt16(result.data[innerICMPOffset + 7])

                        guard origId == identifier, origSeq == sequence else { continue }

                        let latency = Date().timeIntervalSince(sendTime) * 1000.0
                        hopIP = result.srcIP
                        if bestLatency == nil || latency < bestLatency! {
                            bestLatency = latency
                        }
                        allTimedOut = false
                        break

                    } else if icmpType == 129 {
                        // ICMPv6 Echo Reply — target raggiunto
                        let respId = (UInt16(result.data[4]) << 8) | UInt16(result.data[5])
                        let respSeq = (UInt16(result.data[6]) << 8) | UInt16(result.data[7])

                        guard respId == identifier, respSeq == sequence else { continue }

                        let latency = Date().timeIntervalSince(sendTime) * 1000.0
                        hopIP = result.srcIP
                        if bestLatency == nil || latency < bestLatency! {
                            bestLatency = latency
                        }
                        allTimedOut = false
                        reachedTarget = true
                        break
                    }
                }

                if probe < count - 1 {
                    usleep(50_000) // 50ms
                }
            }

            hops.append(TracerouteHopResult(hop: Int(hopLimit), ip: hopIP, latencyMs: bestLatency, timedOut: allTimedOut))

            if reachedTarget { break }
        }

        return encodeResults(hops: hops, targetIP: targetIP, reachedTarget: reachedTarget)
    }

    // MARK: - Encoding comune

    private func encodeResults(hops: [TracerouteHopResult], targetIP: String, reachedTarget: Bool) -> Result<Data, Error> {
        HelperLogger.operations.info("[Traceroute] Completato: \(hops.count) hop, target \(reachedTarget ? "raggiunto" : "non raggiunto") (\(targetIP))")

        do {
            let jsonData = try JSONEncoder().encode(hops)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione traceroute fallita: \(error)"))
        }
    }
}
