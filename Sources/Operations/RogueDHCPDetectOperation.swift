//
//  RogueDHCPDetectOperation.swift
//  HelperDaemon
//
//  Operazione di rilevamento server DHCP rogue tramite pcap.
//  Invia DHCP DISCOVER broadcast e monitora per DHCP OFFER da server imprevisti.
//  Un server DHCP rogue può redirigere tutto il traffico via gateway attaccante.
//  Parser DHCP OFFER: Option 53 (tipo), Option 1 (subnet), Option 3 (router),
//  Option 6 (DNS), Option 51 (lease), Option 54 (server ID).
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//

import Foundation
import os

class RogueDHCPDetectOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    // MARK: - Risultato

    struct DHCPServerResult: Codable {
        let serverIP: String
        let serverMAC: String
        let offeredIP: String
        let subnetMask: String?
        let gateway: String?
        let dnsServers: [String]
        let leaseTime: Int?
        let isExpected: Bool
    }

    // MARK: - Esecuzione

    /// Invia DHCP DISCOVER e raccoglie DHCP OFFER per la durata specificata.
    func execute(interfaceName: String, expectedServerIP: String,
                 durationSeconds: Int32) -> Result<Data, Error> {

        // Ottieni MAC sorgente dell'interfaccia
        guard let srcMAC = PacketBuilder.getInterfaceMAC(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere MAC di \(interfaceName)"))
        }

        // Apri pcap per invio DHCP DISCOVER e cattura OFFER
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 1500, 0, 100, &errbuf)  // snaplen=1500 per catturare DHCP completo
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("pcap_open_live DHCP detection fallito: \(errMsg)"))
        }
        self.pcapHandle = pcap

        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        // Filtro BPF: DHCP OFFER (UDP src port 67, dst port 68)
        let bpfFilter = "udp src port 67 and udp dst port 68"
        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            HelperLogger.forwardWarning(category: "Operations", message: "Impossibile impostare filtro BPF: \(bpfFilter)", tag: "[DHCP]")
        }

        // Genera XID per la transazione DHCP
        let xid = UInt32.random(in: 1...UInt32.max)

        // Costruisci e invia DHCP DISCOVER
        var frame = [UInt8](repeating: 0, count: 342)
        var macBytes = srcMAC
        let frameLen = build_dhcp_discover(&frame, &macBytes, xid)

        let sendResult = frame.prefix(Int(frameLen)).withUnsafeBytes { buf in
            pcap_bridge_send_packet(pcap, buf.baseAddress!.assumingMemoryBound(to: UInt8.self), Int32(frameLen))
        }
        if sendResult != 0 {
            return .failure(HelperError.operationFailed("Invio DHCP DISCOVER fallito"))
        }

        HelperLogger.operations.info("[DHCP] DISCOVER inviato su \(interfaceName), xid=0x\(String(xid, radix: 16)), attesa \(durationSeconds)s")

        // Raccogli DHCP OFFER
        var servers: [DHCPServerResult] = []
        var seenServers: Set<String> = [] // Deduplica per IP server
        let deadline = Date().addingTimeInterval(Double(durationSeconds))

        while Date() < deadline && !isCancelled {
            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length > 0 {
                if let server = parseDHCPOffer(data: packet.data, length: Int(packet.length),
                                                expectedXID: xid, expectedServerIP: expectedServerIP) {
                    if !seenServers.contains(server.serverIP) {
                        seenServers.insert(server.serverIP)
                        servers.append(server)
                        HelperLogger.operations.info("[DHCP] OFFER ricevuto da \(server.serverIP) [\(server.serverMAC)], expected=\(server.isExpected)")
                    }
                }
            } else if result == -1 {
                break
            }
        }

        HelperLogger.operations.info("[DHCP] Detection completato: \(servers.count) server rilevati")

        do {
            let jsonData = try JSONEncoder().encode(servers)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione DHCP detection fallita: \(error)"))
        }
    }

    // MARK: - Parsing DHCP OFFER

    /// Parsa un pacchetto catturato e ne estrae i dati DHCP OFFER.
    private func parseDHCPOffer(data: UnsafePointer<UInt8>, length: Int,
                                 expectedXID: UInt32, expectedServerIP: String) -> DHCPServerResult? {
        // Struttura minima: Ethernet(14) + IP(20) + UDP(8) + DHCP(240 base + 4 magic cookie)
        guard length >= 282 else { return nil }

        let buf = UnsafeBufferPointer(start: data, count: length)

        // Verifica EtherType IPv4
        guard buf[12] == 0x08, buf[13] == 0x00 else { return nil }

        // MAC sorgente Ethernet (server MAC)
        let serverMAC = PacketBuilder.formatMAC([buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]])

        // IP header
        let ipHeaderLen = Int(buf[14] & 0x0F) * 4
        guard ipHeaderLen >= 20 else { return nil }

        // IP sorgente del server DHCP
        let ipOffset = 14
        let serverIP = "\(buf[ipOffset + 12]).\(buf[ipOffset + 13]).\(buf[ipOffset + 14]).\(buf[ipOffset + 15])"

        // UDP header (dopo IP)
        let udpOffset = ipOffset + ipHeaderLen
        guard length >= udpOffset + 8 else { return nil }

        // DHCP payload (dopo UDP)
        let dhcpOffset = udpOffset + 8
        guard length >= dhcpOffset + 240 else { return nil }

        // Verifica DHCP: op = 2 (BOOTREPLY)
        guard buf[dhcpOffset] == 2 else { return nil }

        // Verifica XID
        let xb0 = UInt32(buf[dhcpOffset + 4]) << 24
        let xb1 = UInt32(buf[dhcpOffset + 5]) << 16
        let xb2 = UInt32(buf[dhcpOffset + 6]) << 8
        let xb3 = UInt32(buf[dhcpOffset + 7])
        let rxid = xb0 | xb1 | xb2 | xb3
        guard rxid == expectedXID else { return nil }

        // yiaddr (IP offerto al client, offset 16 nel DHCP)
        let offeredIP = "\(buf[dhcpOffset + 16]).\(buf[dhcpOffset + 17]).\(buf[dhcpOffset + 18]).\(buf[dhcpOffset + 19])"

        // Verifica magic cookie (offset 236 nel DHCP)
        let cookieOffset = dhcpOffset + 236
        guard length >= cookieOffset + 4,
              buf[cookieOffset] == 99, buf[cookieOffset + 1] == 130,
              buf[cookieOffset + 2] == 83, buf[cookieOffset + 3] == 99 else { return nil }

        // Parse DHCP Options
        var optOffset = cookieOffset + 4
        var subnetMask: String?
        var gateway: String?
        var dnsServers: [String] = []
        var leaseTime: Int?
        var dhcpServerID: String?
        var isDHCPOffer = false

        while optOffset < length {
            let option = buf[optOffset]

            if option == 255 { break }  // End
            if option == 0 { optOffset += 1; continue }  // Padding

            guard optOffset + 1 < length else { break }
            let optLen = Int(buf[optOffset + 1])
            guard optOffset + 2 + optLen <= length else { break }

            let optData = optOffset + 2

            switch option {
            case 53:  // DHCP Message Type
                if optLen >= 1 && buf[optData] == 2 {
                    isDHCPOffer = true
                }
            case 1:  // Subnet Mask
                if optLen == 4 {
                    subnetMask = "\(buf[optData]).\(buf[optData+1]).\(buf[optData+2]).\(buf[optData+3])"
                }
            case 3:  // Router (Gateway)
                if optLen >= 4 {
                    gateway = "\(buf[optData]).\(buf[optData+1]).\(buf[optData+2]).\(buf[optData+3])"
                }
            case 6:  // DNS Servers (multipli, 4 byte ciascuno)
                var i = 0
                while i + 3 < optLen {
                    let dns = "\(buf[optData+i]).\(buf[optData+i+1]).\(buf[optData+i+2]).\(buf[optData+i+3])"
                    dnsServers.append(dns)
                    i += 4
                }
            case 51:  // Lease Time
                if optLen == 4 {
                    let b0 = UInt32(buf[optData]) << 24
                    let b1 = UInt32(buf[optData+1]) << 16
                    let b2 = UInt32(buf[optData+2]) << 8
                    let b3 = UInt32(buf[optData+3])
                    leaseTime = Int(b0 | b1 | b2 | b3)
                }
            case 54:  // DHCP Server Identifier
                if optLen == 4 {
                    dhcpServerID = "\(buf[optData]).\(buf[optData+1]).\(buf[optData+2]).\(buf[optData+3])"
                }
            default:
                break
            }

            optOffset += 2 + optLen
        }

        // Deve essere un DHCP OFFER
        guard isDHCPOffer else { return nil }

        // Usa server ID se disponibile, altrimenti IP sorgente
        let effectiveServerIP = dhcpServerID ?? serverIP

        return DHCPServerResult(
            serverIP: effectiveServerIP,
            serverMAC: serverMAC,
            offeredIP: offeredIP,
            subnetMask: subnetMask,
            gateway: gateway,
            dnsServers: dnsServers,
            leaseTime: leaseTime,
            isExpected: effectiveServerIP == expectedServerIP
        )
    }
}
