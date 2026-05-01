//
//  ICMPPingOperation.swift
//  HelperDaemon
//
//  Operazione ICMP ping usando raw socket.
//  Invia ICMP Echo Request e attende Echo Reply per misurare
//  latenza precisa e TTL. Ritorna {latencyMs, ttl, packetLoss} come JSON Data.
//

import Foundation
import os

class ICMPPingOperation: BaseOperation {

    override func cancel() {
        super.cancel()
    }

    /// Risultato ICMP ping
    struct ICMPPingResult: Codable {
        let latencyMs: Double?
        let ttl: Int?
        let packetLoss: Double    // 0.0 - 1.0
        let sent: Int
        let received: Int
        let minLatency: Double?
        let maxLatency: Double?
        let avgLatency: Double?
    }

    /// Esegue ICMP ping raw (dual-stack IPv4/IPv6)
    func execute(targetIP: String, count: Int32, timeoutMs: Int32,
                 interfaceName: String) -> Result<Data, Error> {

        if PacketBuilder.isIPv6(targetIP) {
            return executeIPv6(targetIP: targetIP, count: count, timeoutMs: timeoutMs,
                               interfaceName: interfaceName)
        } else {
            return executeIPv4(targetIP: targetIP, count: count, timeoutMs: timeoutMs,
                               interfaceName: interfaceName)
        }
    }

    // MARK: - IPv4

    private func executeIPv4(targetIP: String, count: Int32, timeoutMs: Int32,
                             interfaceName: String) -> Result<Data, Error> {

        guard let srcIPStr = PacketBuilder.getInterfaceIP(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere IP di \(interfaceName)"))
        }

        let srcIP = PacketBuilder.ipToUInt32(srcIPStr)
        let dstIP = PacketBuilder.ipToUInt32(targetIP)

        guard srcIP > 0, dstIP > 0 else {
            return .failure(HelperError.invalidParameters("IP non validi"))
        }

        // Crea raw socket ICMP
        let sockfd = raw_socket_create(Int32(IPPROTO_ICMP))
        guard sockfd >= 0 else {
            return .failure(HelperError.socketError("Impossibile creare raw socket ICMP: errno=\(errno)"))
        }
        raw_socket_set_hdrincl(sockfd)

        // Bind socket all'interfaccia fisica — bypassa routing table VPN
        // Con VPN attiva, senza binding il kernel instrada ICMP nel tunnel
        // e i ping non raggiungono la LAN locale (Camera Locator fallisce)
        var ifindex = if_nametoindex(interfaceName)
        if ifindex > 0 {
            setsockopt(sockfd, IPPROTO_IP, IP_BOUND_IF, &ifindex, socklen_t(MemoryLayout<UInt32>.size))
        }

        // Timeout per singolo recv
        let perPacketTimeout = max(timeoutMs / max(count, 1), 500)
        raw_socket_set_recv_timeout(sockfd, perPacketTimeout)

        defer { raw_socket_close(sockfd) }

        let identifier = UInt16(getpid() & 0xFFFF)
        var latencies: [Double] = []
        var lastTTL: Int?
        var sent = 0
        var received = 0

        for seq in 0..<count {
            guard !isCancelled else {
                return .failure(HelperError.cancelled)
            }

            let sequence = UInt16(seq)
            let sendTime = Date()

            // Costruisci e invia ICMP Echo Request
            let packet = PacketBuilder.buildICMPEchoPacket(
                srcIP: srcIP, dstIP: dstIP,
                identifier: identifier, sequence: sequence
            )

            var destAddr = sockaddr_in()
            destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            destAddr.sin_family = sa_family_t(AF_INET)
            destAddr.sin_addr.s_addr = CFSwapInt32HostToBig(dstIP)

            let sentBytes = packet.withUnsafeBytes { buf in
                withUnsafePointer(to: &destAddr) { addr in
                    addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(sockfd, buf.baseAddress, buf.count, 0, sa,
                               socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }

            sent += 1

            guard sentBytes > 0 else { continue }

            // Attendi Echo Reply
            let deadline = sendTime.addingTimeInterval(Double(perPacketTimeout) / 1000.0)

            while Date() < deadline {
                var recvBuf = [UInt8](repeating: 0, count: 256)
                let n = recv(sockfd, &recvBuf, recvBuf.count, 0)

                guard n > 0 else {
                    if errno == EAGAIN || errno == EWOULDBLOCK { break }
                    continue
                }

                // Parse IP header
                let ipHeaderLen = Int(recvBuf[0] & 0x0F) * 4
                guard n >= ipHeaderLen + 8 else { continue }

                // Verifica ICMP Echo Reply (type=0, code=0)
                let icmpType = recvBuf[ipHeaderLen]
                let icmpCode = recvBuf[ipHeaderLen + 1]

                guard icmpType == 0, icmpCode == 0 else { continue }

                // Verifica identifier e sequence
                let respId = (UInt16(recvBuf[ipHeaderLen + 4]) << 8) | UInt16(recvBuf[ipHeaderLen + 5])
                let respSeq = (UInt16(recvBuf[ipHeaderLen + 6]) << 8) | UInt16(recvBuf[ipHeaderLen + 7])

                guard respId == identifier, respSeq == sequence else { continue }

                // Calcola latenza
                let latency = Date().timeIntervalSince(sendTime) * 1000.0
                latencies.append(latency)
                received += 1

                // TTL dall'header IP
                lastTTL = Int(recvBuf[8])

                break
            }

            // Pausa tra pacchetti (solo se non è l'ultimo)
            if seq < count - 1 {
                usleep(100_000) // 100ms
            }
        }

        return buildResult(targetIP: targetIP, latencies: latencies, lastTTL: lastTTL,
                           sent: sent, received: received)
    }

    // MARK: - IPv6

    /// ICMPv6 ping: IPPROTO_ICMPV6 raw socket, kernel genera header IPv6,
    /// kernel calcola checksum ICMPv6 (mettiamo 0), hop limit via recvmsg ancillary data.
    /// ICMPv6 Echo Reply = type 129 (non 0 come ICMP).
    private func executeIPv6(targetIP: String, count: Int32, timeoutMs: Int32,
                             interfaceName: String) -> Result<Data, Error> {

        let isLinkLocal = PacketBuilder.isIPv6LinkLocal(targetIP)
        guard let srcIPv6Str = PacketBuilder.getInterfaceIPv6(interfaceName, preferGlobal: !isLinkLocal) else {
            return .failure(HelperError.operationFailed("Nessun IPv6 su \(interfaceName)"))
        }

        guard let srcAddr = PacketBuilder.parseIPv6(srcIPv6Str) else {
            return .failure(HelperError.invalidParameters("IPv6 sorgente non valido: \(srcIPv6Str)"))
        }

        guard var dstAddr = PacketBuilder.parseIPv6(targetIP) else {
            return .failure(HelperError.invalidParameters("IPv6 destinazione non valido: \(targetIP)"))
        }

        let scopeId = PacketBuilder.scopeID(interfaceName)

        // Crea raw socket ICMPv6
        let sockfd = PacketBuilder.createRawSocketV6(protocol: Int32(IPPROTO_ICMPV6))
        guard sockfd >= 0 else {
            return .failure(HelperError.socketError("Impossibile creare raw socket ICMPv6: errno=\(errno)"))
        }

        // Bind a source IPv6
        guard PacketBuilder.bindRawSocketV6(sockfd, interface: interfaceName, srcAddr: srcAddr) else {
            raw_socket_close(sockfd)
            return .failure(HelperError.socketError("Bind ICMPv6 fallito: errno=\(errno)"))
        }

        let perPacketTimeout = max(timeoutMs / max(count, 1), 500)
        raw_socket_set_recv_timeout(sockfd, perPacketTimeout)

        defer { raw_socket_close(sockfd) }

        let identifier = UInt16(getpid() & 0xFFFF)
        var latencies: [Double] = []
        var lastTTL: Int?
        var sent = 0
        var received = 0

        for seq in 0..<count {
            guard !isCancelled else {
                return .failure(HelperError.cancelled)
            }

            let sequence = UInt16(seq)
            let sendTime = Date()

            // Costruisci ICMPv6 Echo Request (SENZA header IPv6, checksum=0 → kernel lo calcola)
            let payload = PacketBuilder.buildICMPv6EchoPayload(
                identifier: identifier, sequence: sequence
            )

            // Destinazione sockaddr_in6
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

            sent += 1

            guard sentBytes > 0 else { continue }

            // Attendi ICMPv6 Echo Reply (type 129)
            let deadline = sendTime.addingTimeInterval(Double(perPacketTimeout) / 1000.0)

            while Date() < deadline {
                // Usa recvmsg per ottenere hop limit dagli ancillary data
                guard let result = PacketBuilder.recvmsgV6(sockfd, bufferSize: 256) else {
                    if errno == EAGAIN || errno == EWOULDBLOCK { break }
                    continue
                }

                // IPv6: ICMPv6 header a offset 0 (no IPv6 header nel buffer)
                guard result.count >= 8 else { continue }

                // ICMPv6 Echo Reply: type=129, code=0
                let icmpType = result.data[0]
                let icmpCode = result.data[1]

                guard icmpType == 129, icmpCode == 0 else { continue }

                // Verifica identifier e sequence
                let respId = (UInt16(result.data[4]) << 8) | UInt16(result.data[5])
                let respSeq = (UInt16(result.data[6]) << 8) | UInt16(result.data[7])

                guard respId == identifier, respSeq == sequence else { continue }

                let latency = Date().timeIntervalSince(sendTime) * 1000.0
                latencies.append(latency)
                received += 1

                // Hop limit dagli ancillary data (equivalente TTL per IPv6)
                if result.hopLimit >= 0 {
                    lastTTL = result.hopLimit
                }

                break
            }

            if seq < count - 1 {
                usleep(100_000) // 100ms
            }
        }

        return buildResult(targetIP: targetIP, latencies: latencies, lastTTL: lastTTL,
                           sent: sent, received: received)
    }

    // MARK: - Risultato comune

    private func buildResult(targetIP: String, latencies: [Double], lastTTL: Int?,
                             sent: Int, received: Int) -> Result<Data, Error> {
        let packetLoss = sent > 0 ? Double(sent - received) / Double(sent) : 1.0
        let minLat = latencies.min()
        let maxLat = latencies.max()
        let avgLat = latencies.isEmpty ? nil : latencies.reduce(0, +) / Double(latencies.count)

        let result = ICMPPingResult(
            latencyMs: avgLat,
            ttl: lastTTL,
            packetLoss: packetLoss,
            sent: sent,
            received: received,
            minLatency: minLat,
            maxLatency: maxLat,
            avgLatency: avgLat
        )

        do {
            let jsonData = try JSONEncoder().encode(result)
            HelperLogger.operations.info("[ICMP] Ping \(targetIP): \(received)/\(sent), avg=\(String(format: "%.1f", avgLat ?? 0))ms, ttl=\(lastTTL ?? 0)")
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione fallita: \(error)"))
        }
    }
}
