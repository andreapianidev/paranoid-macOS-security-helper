//
//  PassiveCaptureOperation.swift
//  HelperDaemon
//
//  Operazione cattura passiva del traffico di rete usando pcap in
//  modalità promiscua. Filtra mDNS, SSDP, NetBIOS, DHCP per
//  discovery dispositivi senza invio di pacchetti.
//  Ritorna array di dispositivi trovati come JSON Data.
//

import Foundation
import os

class PassiveCaptureOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    /// Dispositivo trovato tramite cattura passiva
    struct PassiveDevice: Codable, Hashable {
        let ip: String
        var mac: String?
        var hostname: String?
        var source: String  // "mDNS", "SSDP", "NetBIOS", "DHCP", "ARP"
        var dhcpFingerprint: String?  // Option 55 — lista byte comma-separated (es. "1,28,2,3,15,6,119,12")
        var dhcpVendor: String?       // Option 60 — Vendor Class Identifier (es. "android-dhcp-14", "MSFT 5.0")
        var dhcpClientId: String?     // Option 61 — Client Identifier (può contenere MAC reale su Android vecchi)
    }

    /// Esegue cattura passiva per la durata specificata
    func execute(interfaceName: String, durationSeconds: Int32,
                 filterTypes: [String]) -> Result<Data, Error> {

        // Costruisci filtro BPF combinato
        let bpfFilter = buildBPFFilter(filterTypes: filterTypes)

        // Apri pcap in modalità promiscua
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 1500, 1, 100, &errbuf) // promisc=1
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("pcap_open_live promiscuo fallito: \(errMsg)"))
        }
        self.pcapHandle = pcap

        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        // Imposta filtro
        if !bpfFilter.isEmpty {
            let filterResult = bpfFilter.withCString { filter in
                pcap_bridge_set_filter(pcap, filter)
            }
            if filterResult != 0 {
                HelperLogger.forwardWarning(category: "Operations", message: "Impossibile impostare filtro BPF: \(bpfFilter)", tag: "[Passive]")
            }
        }

        var devices: Set<PassiveDevice> = []
        let deadline = Date().addingTimeInterval(Double(durationSeconds))

        while Date() < deadline && !isCancelled {
            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length > 0 {
                if let device = parsePacket(data: packet.data, length: Int(packet.length)) {
                    devices.insert(device)
                }
            } else if result == -1 {
                break
            }
        }

        let devicesArray = Array(devices)

        do {
            let jsonData = try JSONEncoder().encode(devicesArray)
            HelperLogger.operations.info("[Passive] Passive discovery completata: \(devicesArray.count) dispositivi su \(interfaceName)")
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione fallita: \(error)"))
        }
    }

    // MARK: - Filtro BPF

    /// Costruisce il filtro BPF per i tipi di traffico richiesti
    private func buildBPFFilter(filterTypes: [String]) -> String {
        let types = filterTypes.isEmpty ? ["mDNS", "SSDP", "NetBIOS", "DHCP", "ARP"] : filterTypes
        var filters: [String] = []

        for type in types {
            switch type.lowercased() {
            case "mdns":
                filters.append("udp port 5353")
            case "ssdp":
                filters.append("udp port 1900")
            case "netbios":
                filters.append("udp port 137 or udp port 138")
            case "dhcp":
                filters.append("udp port 67 or udp port 68")
            case "arp":
                filters.append("arp")
            default:
                break
            }
        }

        return filters.joined(separator: " or ")
    }

    // MARK: - Parsing Pacchetti

    /// Parsa un pacchetto catturato ed estrae informazioni sul dispositivo
    private func parsePacket(data: UnsafePointer<UInt8>, length: Int) -> PassiveDevice? {
        guard length >= 14 else { return nil }

        let buffer = UnsafeBufferPointer(start: data, count: length)

        // Ethernet header
        let etherType = (UInt16(buffer[12]) << 8) | UInt16(buffer[13])

        // MAC sorgente
        let srcMAC = PacketBuilder.formatMAC([buffer[6], buffer[7], buffer[8],
                                               buffer[9], buffer[10], buffer[11]])

        switch etherType {
        case 0x0806: // ARP
            return parseARPPacket(buffer: buffer, srcMAC: srcMAC)
        case 0x0800: // IPv4
            return parseIPv4Packet(buffer: buffer, srcMAC: srcMAC)
        default:
            return nil
        }
    }

    /// Parsa un pacchetto ARP
    private func parseARPPacket(buffer: UnsafeBufferPointer<UInt8>, srcMAC: String) -> PassiveDevice? {
        guard buffer.count >= 42 else { return nil }

        // Solo ARP reply o request con IP valido
        let opcode = (UInt16(buffer[20]) << 8) | UInt16(buffer[21])
        guard opcode == 1 || opcode == 2 else { return nil }

        // Sender IP (offset 28-31)
        let ip = "\(buffer[28]).\(buffer[29]).\(buffer[30]).\(buffer[31])"
        let mac = PacketBuilder.formatMAC([buffer[22], buffer[23], buffer[24],
                                            buffer[25], buffer[26], buffer[27]])

        guard mac != "FF:FF:FF:FF:FF:FF", mac != "00:00:00:00:00:00" else { return nil }
        guard ip != "0.0.0.0" else { return nil }

        return PassiveDevice(ip: ip, mac: mac, hostname: nil, source: "ARP")
    }

    /// Parsa un pacchetto IPv4
    private func parseIPv4Packet(buffer: UnsafeBufferPointer<UInt8>, srcMAC: String) -> PassiveDevice? {
        guard buffer.count >= 34 else { return nil }

        let ipHeaderLen = Int(buffer[14] & 0x0F) * 4
        let protocol_ = buffer[23]

        // IP sorgente
        let srcIP = "\(buffer[26]).\(buffer[27]).\(buffer[28]).\(buffer[29])"

        guard protocol_ == 17 else { return nil } // Solo UDP

        let udpOffset = 14 + ipHeaderLen
        guard buffer.count >= udpOffset + 8 else { return nil }

        let dstPort = (UInt16(buffer[udpOffset + 2]) << 8) | UInt16(buffer[udpOffset + 3])

        switch dstPort {
        case 5353: // mDNS
            let hostname = parseMDNSHostname(buffer: buffer, udpOffset: udpOffset)
            return PassiveDevice(ip: srcIP, mac: srcMAC, hostname: hostname, source: "mDNS")

        case 1900: // SSDP
            return PassiveDevice(ip: srcIP, mac: srcMAC, hostname: nil, source: "SSDP")

        case 137, 138: // NetBIOS
            let hostname = parseNetBIOSHostname(buffer: buffer, udpOffset: udpOffset)
            return PassiveDevice(ip: srcIP, mac: srcMAC, hostname: hostname, source: "NetBIOS")

        case 67, 68: // DHCP
            let dhcpOptions = parseDHCPOptions(buffer: buffer, udpOffset: udpOffset)
            var device = PassiveDevice(ip: srcIP, mac: srcMAC, hostname: dhcpOptions.hostname, source: "DHCP")
            device.dhcpFingerprint = dhcpOptions.fingerprint
            device.dhcpVendor = dhcpOptions.vendor
            device.dhcpClientId = dhcpOptions.clientId
            return device

        default:
            return nil
        }
    }

    // MARK: - Parser Protocolli

    /// Estrae hostname da un pacchetto mDNS (semplificato)
    private func parseMDNSHostname(buffer: UnsafeBufferPointer<UInt8>, udpOffset: Int) -> String? {
        let dnsOffset = udpOffset + 8
        guard buffer.count > dnsOffset + 12 else { return nil }

        // Prova a estrarre il primo nome dal DNS
        var nameOffset = dnsOffset + 12
        var name = ""

        while nameOffset < buffer.count {
            let labelLen = Int(buffer[nameOffset])
            if labelLen == 0 { break }
            if labelLen > 63 { break } // Compression pointer

            nameOffset += 1
            guard nameOffset + labelLen <= buffer.count else { break }

            let label = (0..<labelLen).map { String(UnicodeScalar(buffer[nameOffset + $0])) }.joined()
            if !name.isEmpty { name += "." }
            name += label
            nameOffset += labelLen
        }

        // Rimuovi ".local" se presente
        if name.hasSuffix(".local") {
            name = String(name.dropLast(6))
        }
        // Rimuovi prefisso servizio
        if name.hasPrefix("_") { return nil }

        return name.isEmpty ? nil : name
    }

    /// Estrae hostname da NetBIOS (semplificato)
    private func parseNetBIOSHostname(buffer: UnsafeBufferPointer<UInt8>, udpOffset: Int) -> String? {
        let nbOffset = udpOffset + 8
        guard buffer.count > nbOffset + 12 else { return nil }

        // NetBIOS name è encoded nei primi 32 byte dopo l'header
        let nameStart = nbOffset + 12 + 1 // Skip length byte
        guard nameStart + 32 <= buffer.count else { return nil }

        var name = ""
        for i in stride(from: 0, to: 32, by: 2) {
            let hi = Int(buffer[nameStart + i]) - 0x41
            let lo = Int(buffer[nameStart + i + 1]) - 0x41
            guard hi >= 0, hi < 16, lo >= 0, lo < 16 else { break }
            guard let scalar = UnicodeScalar(hi * 16 + lo) else { break }
            let ch = Character(scalar)
            if ch == " " { break }
            name.append(ch)
        }

        return name.isEmpty ? nil : name
    }

    /// Estrae hostname (Option 12), fingerprint (Option 55), vendor (Option 60) e client ID (Option 61) da DHCP
    private func parseDHCPOptions(buffer: UnsafeBufferPointer<UInt8>, udpOffset: Int)
        -> (hostname: String?, fingerprint: String?, vendor: String?, clientId: String?) {
        let dhcpOffset = udpOffset + 8
        // DHCP options iniziano a offset 240 (dopo header BOOTP fisso)
        let optionsStart = dhcpOffset + 240
        guard buffer.count > optionsStart + 4 else { return (nil, nil, nil, nil) }

        // Verifica magic cookie DHCP
        guard buffer[optionsStart] == 99, buffer[optionsStart + 1] == 130,
              buffer[optionsStart + 2] == 83, buffer[optionsStart + 3] == 99 else { return (nil, nil, nil, nil) }

        var hostname: String?
        var fingerprint: String?
        var vendor: String?
        var clientId: String?

        var offset = optionsStart + 4
        while offset < buffer.count - 2 {
            let optionCode = buffer[offset]
            if optionCode == 255 { break } // End
            if optionCode == 0 { offset += 1; continue } // Padding

            let optionLen = Int(buffer[offset + 1])
            offset += 2
            guard offset + optionLen <= buffer.count else { break }

            switch optionCode {
            case 12: // Hostname
                if optionLen > 0 {
                    hostname = (0..<optionLen).map { String(UnicodeScalar(buffer[offset + $0])) }.joined()
                }
            case 55: // Parameter Request List — fingerprint OS-specifico
                if optionLen > 0 {
                    fingerprint = (0..<optionLen).map { String(buffer[offset + $0]) }.joined(separator: ",")
                }
            case 60: // Vendor Class Identifier (es. "android-dhcp-14", "MSFT 5.0", "dhcpcd-9.4.1:Linux-6.1")
                if optionLen > 0 {
                    vendor = (0..<optionLen).compactMap { i -> String? in
                        let byte = buffer[offset + Int(i)]
                        return byte >= 32 && byte < 127 ? String(UnicodeScalar(byte)) : nil
                    }.joined()
                }
            case 61: // Client Identifier — tipo (1 byte) + dati
                // Tipo 1 = Ethernet hardware address (6 byte MAC), può essere il MAC reale
                // su Android vecchi anche con MAC random su IPv4
                if optionLen >= 7, buffer[offset] == 1 {
                    // Tipo 1: hardware address Ethernet → formato MAC XX:XX:XX:XX:XX:XX
                    clientId = (1..<min(optionLen, 7)).map {
                        String(format: "%02X", buffer[offset + $0])
                    }.joined(separator: ":")
                } else if optionLen > 1 {
                    // Tipo != 1: testo generico (DUID, FQDN, ecc.)
                    clientId = (1..<optionLen).compactMap { i -> String? in
                        let byte = buffer[offset + Int(i)]
                        return byte >= 32 && byte < 127 ? String(UnicodeScalar(byte)) : nil
                    }.joined()
                }
            default:
                break
            }

            offset += optionLen
        }

        return (hostname, fingerprint, vendor, clientId)
    }
}
