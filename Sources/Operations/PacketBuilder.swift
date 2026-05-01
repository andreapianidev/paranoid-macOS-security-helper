//
//  PacketBuilder.swift
//  HelperDaemon
//
//  Utility Swift per costruzione e parsing pacchetti di rete.
//  Wrappa le funzioni C di raw_socket.h con API Swift-friendly.
//

import Foundation

enum PacketBuilder {

    // MARK: - Costruzione Pacchetti

    /// Costruisce un pacchetto TCP SYN completo (IP + TCP + opzioni)
    static func buildSYNPacket(srcIP: UInt32, dstIP: UInt32,
                                srcPort: UInt16, dstPort: UInt16,
                                seqNum: UInt32 = UInt32.random(in: 0...UInt32.max)) -> Data {
        var packet = [UInt8](repeating: 0, count: 64)
        let length = build_syn_packet(&packet, srcIP, dstIP, srcPort, dstPort, seqNum)
        return Data(packet.prefix(Int(length)))
    }

    /// Costruisce un pacchetto ICMP Echo Request
    static func buildICMPEchoPacket(srcIP: UInt32, dstIP: UInt32,
                                     identifier: UInt16, sequence: UInt16) -> Data {
        var packet = [UInt8](repeating: 0, count: 64)
        let length = build_icmp_echo_packet(&packet, srcIP, dstIP, identifier, sequence)
        return Data(packet.prefix(Int(length)))
    }

    /// Costruisce un frame ARP Request (Ethernet + ARP)
    static func buildARPRequest(srcMAC: [UInt8], srcIP: UInt32, dstIP: UInt32) -> Data {
        var frame = [UInt8](repeating: 0, count: 42)
        var mac = srcMAC
        let length = build_arp_request(&frame, &mac, srcIP, dstIP)
        return Data(frame.prefix(Int(length)))
    }

    // MARK: - Utility IP

    /// Converte stringa IP in UInt32 (host byte order)
    static func ipToUInt32(_ ip: String) -> UInt32 {
        return ip.withCString { ip_to_uint32($0) }
    }

    /// Converte UInt32 (host byte order) in stringa IP
    static func uint32ToIP(_ value: UInt32) -> String {
        var buffer = [CChar](repeating: 0, count: 16)
        uint32_to_ip(value, &buffer)
        return String(cString: buffer)
    }

    /// Genera lista di IP da startIP a endIP
    static func generateIPRange(start: String, end: String) -> [String] {
        let startNum = ipToUInt32(start)
        let endNum = ipToUInt32(end)
        guard startNum > 0, endNum > 0, endNum >= startNum else { return [] }
        guard endNum - startNum < 65536 else { return [] } // Limita a /16

        return (startNum...endNum).map { uint32ToIP($0) }
    }

    // MARK: - Utility Interfaccia

    /// Ottiene l'indirizzo IP dell'interfaccia
    static func getInterfaceIP(_ interfaceName: String) -> String? {
        var buffer = [CChar](repeating: 0, count: 16)
        let result = interfaceName.withCString { get_interface_ip($0, &buffer) }
        guard result == 0 else { return nil }
        return String(cString: buffer)
    }

    /// Ottiene il MAC address dell'interfaccia
    static func getInterfaceMAC(_ interfaceName: String) -> [UInt8]? {
        var mac = [UInt8](repeating: 0, count: 6)
        let result = interfaceName.withCString { get_interface_mac($0, &mac) }
        guard result == 0 else { return nil }
        return mac
    }

    /// Formatta un MAC address raw in stringa "AA:BB:CC:DD:EE:FF"
    static func formatMAC(_ mac: [UInt8]) -> String {
        return mac.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    // MARK: - IPv6 Detection

    /// Controlla se una stringa è un indirizzo IPv6 (contiene ':')
    static func isIPv6(_ ip: String) -> Bool {
        return ip.withCString { is_ipv6_address($0) != 0 }
    }

    /// Controlla se un indirizzo IPv6 è link-local (fe80::/10)
    static func isIPv6LinkLocal(_ ip: String) -> Bool {
        return ip.withCString { is_ipv6_link_local($0) != 0 }
    }

    // MARK: - IPv6 Utility Interfaccia

    /// Ottiene l'indirizzo IPv6 dell'interfaccia.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - preferGlobal: Se true, preferisce global unicast su link-local
    /// - Returns: Indirizzo IPv6 come stringa, nil se non disponibile
    static func getInterfaceIPv6(_ interfaceName: String, preferGlobal: Bool = true) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = interfaceName.withCString { iface in
            get_interface_ipv6(iface, &buffer, preferGlobal ? 1 : 0)
        }
        guard result == 0 else { return nil }
        return String(cString: buffer)
    }

    /// Ottiene il scope_id (interface index) per un'interfaccia BSD.
    /// Necessario per sockaddr_in6.sin6_scope_id con indirizzi link-local.
    static func scopeID(_ interfaceName: String) -> UInt32 {
        return interfaceName.withCString { get_interface_scope_id($0) }
    }

    /// Parsa una stringa IPv6 in in6_addr. Ritorna nil se non valida.
    static func parseIPv6(_ str: String) -> in6_addr? {
        var addr = in6_addr()
        let result = str.withCString { inet_pton(AF_INET6, $0, &addr) }
        guard result == 1 else { return nil }
        return addr
    }

    // MARK: - IPv6 Costruzione Pacchetti

    /// Costruisce SOLO il payload TCP SYN (header + opzioni), SENZA header IPv6.
    /// Il campo checksum è a 0 — va calcolato con computeTCP6Checksum() e patchato.
    static func buildTCPSYNPayload(srcPort: UInt16, dstPort: UInt16,
                                    seqNum: UInt32 = UInt32.random(in: 0...UInt32.max)) -> Data {
        var buf = [UInt8](repeating: 0, count: 48)
        let length = build_tcp_syn_payload(&buf, srcPort, dstPort, seqNum)
        return Data(buf.prefix(Int(length)))
    }

    /// Costruisce SOLO il payload TCP RST, SENZA header IPv6.
    /// Il campo checksum è a 0 — va calcolato con computeTCP6Checksum() e patchato.
    static func buildTCPRSTPayload(srcPort: UInt16, dstPort: UInt16,
                                    seqNum: UInt32) -> Data {
        var buf = [UInt8](repeating: 0, count: 24)
        let length = build_tcp_rst_payload(&buf, srcPort, dstPort, seqNum)
        return Data(buf.prefix(Int(length)))
    }

    /// Costruisce SOLO il payload ICMPv6 Echo Request, SENZA header IPv6.
    /// Il kernel calcola il checksum ICMPv6 automaticamente.
    static func buildICMPv6EchoPayload(identifier: UInt16, sequence: UInt16) -> Data {
        var buf = [UInt8](repeating: 0, count: 48)
        let length = build_icmpv6_echo(&buf, identifier, sequence)
        return Data(buf.prefix(Int(length)))
    }

    // MARK: - IPv6 Checksum

    /// Calcola il checksum TCP con pseudo-header IPv6.
    /// - Parameters:
    ///   - srcIPv6: Indirizzo IPv6 sorgente
    ///   - dstIPv6: Indirizzo IPv6 destinazione
    ///   - tcpSegment: Segmento TCP completo (header + opzioni)
    /// - Returns: Checksum in network byte order
    static func computeTCP6Checksum(srcIPv6: in6_addr, dstIPv6: in6_addr,
                                     tcpSegment: Data) -> UInt16 {
        var src = srcIPv6
        var dst = dstIPv6
        return tcpSegment.withUnsafeBytes { buf in
            guard let ptr = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return tcp6_checksum(&src, &dst, ptr, Int32(buf.count))
        }
    }

    /// Patcha il campo checksum in un segmento TCP (offset 16-17 nell'header).
    /// - Parameters:
    ///   - segment: Segmento TCP mutabile
    ///   - checksum: Checksum calcolato
    static func patchTCPChecksum(_ segment: inout Data, checksum: UInt16) {
        guard segment.count >= 18 else { return }
        // Checksum TCP è a offset 16-17 nell'header TCP
        segment[16] = UInt8((checksum >> 8) & 0xFF)
        segment[17] = UInt8(checksum & 0xFF)
    }

    // MARK: - IPv6 Socket Helper

    /// Crea un raw socket IPv6 per il protocollo specificato.
    /// Il kernel genera l'header IPv6 automaticamente (no IPV6_HDRINCL su macOS).
    static func createRawSocketV6(protocol proto: Int32) -> Int32 {
        return raw_socket_create_v6(proto)
    }

    /// Associa un raw socket IPv6 a un indirizzo sorgente e interfaccia.
    static func bindRawSocketV6(_ sockfd: Int32, interface: String, srcAddr: in6_addr?) -> Bool {
        if var addr = srcAddr {
            return interface.withCString { iface in
                raw_socket_bind_v6(sockfd, iface, &addr) == 0
            }
        } else {
            return interface.withCString { iface in
                raw_socket_bind_v6(sockfd, iface, nil) == 0
            }
        }
    }

    /// Riceve dati da un raw socket IPv6 con hop limit (recvmsg + ancillary data).
    /// - Returns: Tuple (data ricevuta, indirizzo sorgente IPv6 stringa, hop limit) o nil
    static func recvmsgV6(_ sockfd: Int32, bufferSize: Int = 512,
                           timeout: Int32 = 0) -> (data: [UInt8], count: Int, srcIP: String, hopLimit: Int)? {
        if timeout > 0 {
            raw_socket_set_recv_timeout(sockfd, timeout)
        }

        var buf = [UInt8](repeating: 0, count: bufferSize)
        var from = sockaddr_in6()
        var hopLimit: Int32 = -1
        let n = raw_socket_recvmsg_v6(sockfd, &buf, Int32(bufferSize), &from, &hopLimit)
        guard n > 0 else { return nil }

        // Converti indirizzo sorgente in stringa
        var srcBuf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var srcAddr = from.sin6_addr
        inet_ntop(AF_INET6, &srcAddr, &srcBuf, socklen_t(INET6_ADDRSTRLEN))
        let srcIP = String(cString: srcBuf)

        return (data: buf, count: Int(n), srcIP: srcIP, hopLimit: Int(hopLimit))
    }
}
