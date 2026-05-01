//
//  UDPScanOperation.swift
//  HelperDaemon
//
//  Operazione UDP scan. Invia datagram UDP (vuoto o payload specifico
//  per DNS/SNMP/NTP), cattura ICMP port-unreachable per determinare
//  stato porta. Ritorna [{port, state}] come JSON Data.
//

import Foundation
import os

class UDPScanOperation: BaseOperation {

    override func cancel() {
        super.cancel()
    }

    /// Risultato singola porta UDP
    struct UDPPortResult: Codable {
        let port: Int
        let state: String  // "open|filtered", "closed", "open"
    }

    /// Payload specifici per protocolli UDP comuni
    private static let protocolPayloads: [Int32: Data] = {
        var payloads: [Int32: Data] = [:]

        // DNS query per "version.bind" (classe CHAOS)
        payloads[53] = Data([
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Authority/Additional: 0
            0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, // "version"
            0x04, 0x62, 0x69, 0x6E, 0x64, // "bind"
            0x00,       // Root
            0x00, 0x10, // Type: TXT
            0x00, 0x03  // Class: CH (CHAOS)
        ])

        // SNMP GetRequest (community "public", sysDescr.0)
        payloads[161] = Data([
            0x30, 0x29, // SEQUENCE
            0x02, 0x01, 0x00, // INTEGER: version 1
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // OCTET STRING: "public"
            0xA0, 0x1C, // GetRequest
            0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id: 1
            0x02, 0x01, 0x00, // error-status: 0
            0x02, 0x01, 0x00, // error-index: 0
            0x30, 0x0E, // varbind list
            0x30, 0x0C, // varbind
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: sysDescr.0
            0x05, 0x00  // NULL
        ])

        // NTP Version Request (Mode 3 = Client)
        var ntpPacket = Data(repeating: 0, count: 48)
        ntpPacket[0] = 0x1B // LI=0, VN=3, Mode=3
        payloads[123] = ntpPacket

        // NetBIOS Name Service query (NBTSTAT)
        payloads[137] = Data([
            0x80, 0x01, // Transaction ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, // Encoded "*"
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x00, 0x00, 0x21, 0x00, 0x01 // Type: NBSTAT, Class: IN
        ])

        // SSDP M-SEARCH
        let ssdpStr = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
        payloads[1900] = ssdpStr.data(using: .utf8) ?? Data()

        return payloads
    }()

    /// Esegue UDP scan sulle porte specificate con concorrenza controllata
    func execute(targetIP: String, ports: [Int32], interfaceName: String,
                 timeoutMs: Int32) -> Result<Data, Error> {

        var results: [UDPPortResult] = []
        let resultsLock = NSLock()

        // Concorrenza limitata: UDP è rate-limited da ICMP unreachable del kernel
        let maxConcurrent = min(10, max(1, ports.count))
        let semaphore = DispatchSemaphore(value: maxConcurrent)
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

                let result = self?.scanSinglePort(targetIP: targetIP, port: port, timeoutMs: timeoutMs)
                    ?? UDPPortResult(port: Int(port), state: "open|filtered")

                resultsLock.lock()
                results.append(result)
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
            let openCount = results.filter { $0.state == "open" || $0.state == "open|filtered" }.count
            HelperLogger.operations.info("[UDP] Scan completato: \(openCount) porte open/filtered su \(targetIP)")
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione JSON fallita: \(error)"))
        }
    }

    /// Scansiona una singola porta UDP (dual-stack IPv4/IPv6)
    private func scanSinglePort(targetIP: String, port: Int32, timeoutMs: Int32) -> UDPPortResult {
        if PacketBuilder.isIPv6(targetIP) {
            return scanSinglePortIPv6(targetIP: targetIP, port: port, timeoutMs: timeoutMs)
        } else {
            return scanSinglePortIPv4(targetIP: targetIP, port: port, timeoutMs: timeoutMs)
        }
    }

    // MARK: - IPv4

    private func scanSinglePortIPv4(targetIP: String, port: Int32, timeoutMs: Int32) -> UDPPortResult {
        let sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sockfd >= 0 else {
            return UDPPortResult(port: Int(port), state: "open|filtered")
        }
        defer { close(sockfd) }

        // Timeout ricezione
        var tv = timeval()
        tv.tv_sec = Int(timeoutMs) / 1000
        tv.tv_usec = Int32((Int(timeoutMs) % 1000) * 1000)
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var destAddr = sockaddr_in()
        destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destAddr.sin_family = sa_family_t(AF_INET)
        destAddr.sin_port = UInt16(port).bigEndian
        inet_pton(AF_INET, targetIP, &destAddr.sin_addr)

        // Scegli payload
        let payload = UDPScanOperation.protocolPayloads[port] ?? Data([0x00])

        // Invia
        let sent = payload.withUnsafeBytes { buf in
            withUnsafePointer(to: &destAddr) { addr in
                addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(sockfd, buf.baseAddress, buf.count, 0, sa,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        guard sent > 0 else {
            return UDPPortResult(port: Int(port), state: "open|filtered")
        }

        // Attendi risposta
        var recvBuf = [UInt8](repeating: 0, count: 1024)
        var fromAddr = sockaddr_in()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)

        let n = withUnsafeMutablePointer(to: &fromAddr) { addr in
            addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                recvfrom(sockfd, &recvBuf, recvBuf.count, 0, sa, &fromLen)
            }
        }

        if n > 0 {
            // Risposta ricevuta → porta aperta
            return UDPPortResult(port: Int(port), state: "open")
        } else if errno == ECONNREFUSED {
            // ICMP Port Unreachable → porta chiusa
            return UDPPortResult(port: Int(port), state: "closed")
        } else {
            // Timeout o altro → open|filtered
            return UDPPortResult(port: Int(port), state: "open|filtered")
        }
    }

    // MARK: - IPv6

    /// UDP scan IPv6: usa AF_INET6 SOCK_DGRAM (non raw socket).
    /// ICMPv6 Port Unreachable → ECONNREFUSED (stessa logica di IPv4).
    private func scanSinglePortIPv6(targetIP: String, port: Int32, timeoutMs: Int32) -> UDPPortResult {
        let sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard sockfd >= 0 else {
            return UDPPortResult(port: Int(port), state: "open|filtered")
        }
        defer { close(sockfd) }

        // Solo IPv6
        var on: Int32 = 1
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, socklen_t(MemoryLayout<Int32>.size))

        // Timeout ricezione
        var tv = timeval()
        tv.tv_sec = Int(timeoutMs) / 1000
        tv.tv_usec = Int32((Int(timeoutMs) % 1000) * 1000)
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var destAddr6 = sockaddr_in6()
        destAddr6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        destAddr6.sin6_family = sa_family_t(AF_INET6)
        destAddr6.sin6_port = UInt16(port).bigEndian
        inet_pton(AF_INET6, targetIP, &destAddr6.sin6_addr)

        // Scope ID per link-local
        if PacketBuilder.isIPv6LinkLocal(targetIP) {
            destAddr6.sin6_scope_id = PacketBuilder.scopeID("en0")
        }

        // Scegli payload (identico a IPv4 — sono protocol-agnostic)
        let payload = UDPScanOperation.protocolPayloads[port] ?? Data([0x00])

        // Invia
        let sent = payload.withUnsafeBytes { buf in
            withUnsafePointer(to: &destAddr6) { addr in
                addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(sockfd, buf.baseAddress, buf.count, 0, sa,
                           socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }

        guard sent > 0 else {
            return UDPPortResult(port: Int(port), state: "open|filtered")
        }

        // Attendi risposta
        var recvBuf = [UInt8](repeating: 0, count: 1024)
        var fromAddr6 = sockaddr_in6()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in6>.size)

        let n = withUnsafeMutablePointer(to: &fromAddr6) { addr in
            addr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                recvfrom(sockfd, &recvBuf, recvBuf.count, 0, sa, &fromLen)
            }
        }

        if n > 0 {
            return UDPPortResult(port: Int(port), state: "open")
        } else if errno == ECONNREFUSED {
            // ICMPv6 Port Unreachable → porta chiusa
            return UDPPortResult(port: Int(port), state: "closed")
        } else {
            return UDPPortResult(port: Int(port), state: "open|filtered")
        }
    }
}
