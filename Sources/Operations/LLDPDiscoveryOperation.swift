//
//  LLDPDiscoveryOperation.swift
//  HelperDaemon
//
//  Operazione di discovery infrastruttura di rete tramite cattura frame LLDP e CDP.
//  LLDP (IEEE 802.1AB): frame Ethernet con EtherType 0x88CC, TLV chain.
//  CDP (Cisco Discovery Protocol): frame con dst MAC 01:00:0C:CC:CC:CC, LLC/SNAP.
//  Rivela: nome switch, porta, VLAN, IP di gestione, capabilities del dispositivo.
//  LLDP frame ogni 30s, CDP ogni 60s → durationSeconds consigliato 60-120s.
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//

import Foundation
import os

class LLDPDiscoveryOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    // MARK: - Risultato

    struct InfrastructureDevice: Codable {
        let protocolType: String       // "LLDP" o "CDP"
        let deviceName: String?
        let deviceDescription: String?
        let portId: String?
        let managementIP: String?
        let vlan: Int?
        let capabilities: [String]
        let macAddress: String
    }

    // MARK: - Esecuzione

    /// Cattura frame LLDP e CDP per la durata specificata.
    func execute(interfaceName: String, durationSeconds: Int32) -> Result<Data, Error> {

        // Filtro BPF: LLDP (ethertype 0x88cc) OPPURE CDP (dst MAC 01:00:0c:cc:cc:cc)
        let bpfFilter = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"

        // Apri pcap in modalità promiscua (necessario per catturare multicast L2)
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 1500, 1, 100, &errbuf)  // promisc=1
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("pcap_open_live LLDP/CDP fallito: \(errMsg)"))
        }
        self.pcapHandle = pcap

        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            HelperLogger.forwardWarning(category: "Operations", message: "Impossibile impostare filtro BPF: \(bpfFilter)", tag: "[LLDP]")
        }

        var devices: [InfrastructureDevice] = []
        var seenMACs: Set<String> = [] // Deduplica per MAC sorgente
        let deadline = Date().addingTimeInterval(Double(durationSeconds))

        HelperLogger.operations.info("[LLDP] Discovery avviato su \(interfaceName), durata: \(durationSeconds)s")

        while Date() < deadline && !isCancelled {
            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length > 14 {
                let buf = UnsafeBufferPointer(start: packet.data, count: Int(packet.length))

                // MAC sorgente Ethernet (offset 6-11)
                let srcMAC = PacketBuilder.formatMAC([buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]])

                // Deduplica
                guard !seenMACs.contains(srcMAC) else { continue }

                // EtherType (offset 12-13)
                let etherType = (UInt16(buf[12]) << 8) | UInt16(buf[13])

                if etherType == 0x88CC {
                    // LLDP frame
                    if let device = parseLLDP(buf: buf, srcMAC: srcMAC) {
                        seenMACs.insert(srcMAC)
                        devices.append(device)
                        HelperLogger.operations.info("[LLDP] Frame: \(device.deviceName ?? "?") porta \(device.portId ?? "?") da \(srcMAC)")
                    }
                } else if buf[0] == 0x01 && buf[1] == 0x00 && buf[2] == 0x0C &&
                          buf[3] == 0xCC && buf[4] == 0xCC && buf[5] == 0xCC {
                    // CDP frame (check dst MAC)
                    if let device = parseCDP(buf: buf, srcMAC: srcMAC) {
                        seenMACs.insert(srcMAC)
                        devices.append(device)
                        HelperLogger.operations.info("[LLDP] CDP: \(device.deviceName ?? "?") porta \(device.portId ?? "?") da \(srcMAC)")
                    }
                }
            } else if result == -1 {
                break
            }
        }

        HelperLogger.operations.info("[LLDP] Discovery completato: \(devices.count) dispositivi infrastruttura trovati")

        do {
            let jsonData = try JSONEncoder().encode(devices)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione LLDP/CDP fallita: \(error)"))
        }
    }

    // MARK: - Parser LLDP

    /// Parsa un frame LLDP (TLV chain dopo Ethernet header).
    /// TLV format: tipo (7 bit) + lunghezza (9 bit) + valore.
    private func parseLLDP(buf: UnsafeBufferPointer<UInt8>, srcMAC: String) -> InfrastructureDevice? {
        let length = buf.count
        guard length > 14 else { return nil }

        var offset = 14 // Dopo Ethernet header
        var chassisId: String?
        var portId: String?
        var systemName: String?
        var systemDescription: String?
        var managementIP: String?
        var capabilities: [String] = []
        var vlan: Int?

        while offset + 2 <= length {
            // TLV header: 2 byte
            // Tipo: 7 bit MSB, Lunghezza: 9 bit LSB
            let tlvHeader = (UInt16(buf[offset]) << 8) | UInt16(buf[offset + 1])
            let tlvType = Int(tlvHeader >> 9)
            let tlvLen = Int(tlvHeader & 0x01FF)

            offset += 2

            if tlvType == 0 { break }  // End of LLDPDU
            guard offset + tlvLen <= length else { break }

            switch tlvType {
            case 1:  // Chassis ID
                if tlvLen > 1 {
                    let subtype = buf[offset]
                    if subtype == 4 && tlvLen >= 7 {
                        // MAC address
                        chassisId = PacketBuilder.formatMAC(Array(buf[(offset+1)..<(offset+7)]))
                    } else if subtype == 5 || subtype == 7 {
                        // Network address o locally assigned
                        chassisId = String(bytes: buf[(offset+1)..<(offset+tlvLen)], encoding: .utf8)
                    }
                }

            case 2:  // Port ID
                if tlvLen > 1 {
                    let subtype = buf[offset]
                    if subtype == 3 && tlvLen >= 7 {
                        // MAC address
                        portId = PacketBuilder.formatMAC(Array(buf[(offset+1)..<(offset+7)]))
                    } else {
                        // String (interface alias, name, etc.)
                        portId = String(bytes: buf[(offset+1)..<(offset+tlvLen)], encoding: .utf8)?
                            .trimmingCharacters(in: .controlCharacters)
                    }
                }

            case 5:  // System Name
                systemName = String(bytes: buf[offset..<(offset+tlvLen)], encoding: .utf8)?
                    .trimmingCharacters(in: .controlCharacters)

            case 6:  // System Description
                systemDescription = String(bytes: buf[offset..<(offset+tlvLen)], encoding: .utf8)?
                    .trimmingCharacters(in: .controlCharacters)

            case 7:  // System Capabilities
                if tlvLen >= 4 {
                    let caps = (UInt16(buf[offset]) << 8) | UInt16(buf[offset + 1])
                    capabilities = decodeLLDPCapabilities(caps)
                }

            case 8:  // Management Address
                if tlvLen >= 6 {
                    let addrLen = Int(buf[offset])
                    let addrSubtype = buf[offset + 1]
                    if addrSubtype == 1 && addrLen == 5 { // IPv4
                        managementIP = "\(buf[offset+2]).\(buf[offset+3]).\(buf[offset+4]).\(buf[offset+5])"
                    }
                }

            case 127: // Organization-specific TLV
                // IEEE 802.1 (OUI 00:80:C2) - VLAN
                if tlvLen >= 6 && buf[offset] == 0x00 && buf[offset+1] == 0x80 && buf[offset+2] == 0xC2 {
                    let subtype = buf[offset + 3]
                    if subtype == 3 && tlvLen >= 6 {
                        // Port VLAN ID
                        vlan = Int((UInt16(buf[offset+4]) << 8) | UInt16(buf[offset+5]))
                    }
                }

            default:
                break
            }

            offset += tlvLen
        }

        return InfrastructureDevice(
            protocolType: "LLDP",
            deviceName: systemName,
            deviceDescription: systemDescription,
            portId: portId,
            managementIP: managementIP,
            vlan: vlan,
            capabilities: capabilities,
            macAddress: srcMAC
        )
    }

    // MARK: - Parser CDP

    /// Parsa un frame CDP (LLC/SNAP header + TLV chain).
    /// CDP usa LLC/SNAP (8 byte: AA AA 03 00 00 0C 20 00) dopo Ethernet.
    private func parseCDP(buf: UnsafeBufferPointer<UInt8>, srcMAC: String) -> InfrastructureDevice? {
        let length = buf.count
        // Ethernet(14) + LLC/SNAP(8) + CDP version(1) + TTL(1) + checksum(2) = 26 minimo
        guard length >= 26 else { return nil }

        // Verifica LLC/SNAP header: AA AA 03 00 00 0C 20 00
        let llcOffset = 14
        guard buf[llcOffset] == 0xAA, buf[llcOffset+1] == 0xAA, buf[llcOffset+2] == 0x03,
              buf[llcOffset+3] == 0x00, buf[llcOffset+4] == 0x00, buf[llcOffset+5] == 0x0C,
              buf[llcOffset+6] == 0x20, buf[llcOffset+7] == 0x00 else {
            // Se non LLC/SNAP, potrebbe avere formato diverso — prova con offset diretto
            // Alcuni switch usano 802.3 con lunghezza invece di EtherType
            return parseCDPDirect(buf: buf, offset: 22, srcMAC: srcMAC)
        }

        // CDP header: version (1) + TTL (1) + checksum (2) = 4 byte
        let cdpOffset = llcOffset + 8
        guard cdpOffset + 4 <= length else { return nil }

        // CDP TLV chain inizia dopo il CDP header
        return parseCDPTLVs(buf: buf, startOffset: cdpOffset + 4, srcMAC: srcMAC)
    }

    /// Parsing diretto CDP TLV (per frame con formato alternativo)
    private func parseCDPDirect(buf: UnsafeBufferPointer<UInt8>, offset: Int, srcMAC: String) -> InfrastructureDevice? {
        guard offset + 4 <= buf.count else { return nil }
        return parseCDPTLVs(buf: buf, startOffset: offset + 4, srcMAC: srcMAC)
    }

    /// Parsa la catena TLV di CDP
    private func parseCDPTLVs(buf: UnsafeBufferPointer<UInt8>, startOffset: Int,
                               srcMAC: String) -> InfrastructureDevice? {
        let length = buf.count
        var offset = startOffset

        var deviceId: String?
        var portId: String?
        var platform: String?
        var capabilities: [String] = []
        var managementIP: String?
        var vlan: Int?

        while offset + 4 <= length {
            let tlvType = Int((UInt16(buf[offset]) << 8) | UInt16(buf[offset + 1]))
            let tlvLen = Int((UInt16(buf[offset + 2]) << 8) | UInt16(buf[offset + 3]))

            guard tlvLen >= 4, offset + tlvLen <= length else { break }

            let dataOffset = offset + 4
            let dataLen = tlvLen - 4

            switch tlvType {
            case 0x0001:  // Device ID
                if dataLen > 0 {
                    deviceId = String(bytes: buf[dataOffset..<(dataOffset + dataLen)], encoding: .utf8)?
                        .trimmingCharacters(in: .controlCharacters)
                }

            case 0x0003:  // Port ID
                if dataLen > 0 {
                    portId = String(bytes: buf[dataOffset..<(dataOffset + dataLen)], encoding: .utf8)?
                        .trimmingCharacters(in: .controlCharacters)
                }

            case 0x0004:  // Capabilities
                if dataLen >= 4 {
                    let caps = (UInt32(buf[dataOffset]) << 24) |
                               (UInt32(buf[dataOffset + 1]) << 16) |
                               (UInt32(buf[dataOffset + 2]) << 8) |
                                UInt32(buf[dataOffset + 3])
                    capabilities = decodeCDPCapabilities(caps)
                }

            case 0x0005:  // Software Version (usato come description)
                // Skip per ora — può essere molto lungo

                break

            case 0x0006:  // Platform
                if dataLen > 0 {
                    platform = String(bytes: buf[dataOffset..<(dataOffset + dataLen)], encoding: .utf8)?
                        .trimmingCharacters(in: .controlCharacters)
                }

            case 0x0022:  // Management Addresses
                // Format: numAddrs(4) + per addr: protoType(1) + protoLen(1) + proto(protoLen) + addrLen(2) + addr(addrLen)
                // IPv4 NLPID: protoType=1, protoLen=1, proto=0xCC, addrLen=4, addr=4byte IP
                if dataLen >= 13 {
                    let protoType = buf[dataOffset + 4]
                    let protoLen = Int(buf[dataOffset + 5])
                    // Verifica: NLPID (protoType=1), lunghezza proto=1, protocollo IPv4 (0xCC)
                    if protoType == 1 && protoLen == 1 && dataLen >= 6 + protoLen + 2 + 4 {
                        let proto = buf[dataOffset + 6]
                        let ipStart = dataOffset + 6 + protoLen + 2 // dopo proto + addrLen(2)
                        if proto == 0xCC && ipStart + 4 <= dataOffset + dataLen {
                            managementIP = "\(buf[ipStart]).\(buf[ipStart+1]).\(buf[ipStart+2]).\(buf[ipStart+3])"
                        }
                    }
                }

            case 0x000A:  // Native VLAN
                if dataLen >= 2 {
                    vlan = Int((UInt16(buf[dataOffset]) << 8) | UInt16(buf[dataOffset + 1]))
                }

            default:
                break
            }

            offset += tlvLen
        }

        // Almeno un campo significativo
        guard deviceId != nil || portId != nil || platform != nil else { return nil }

        return InfrastructureDevice(
            protocolType: "CDP",
            deviceName: deviceId,
            deviceDescription: platform,
            portId: portId,
            managementIP: managementIP,
            vlan: vlan,
            capabilities: capabilities,
            macAddress: srcMAC
        )
    }

    // MARK: - Decodifica Capabilities

    /// Decodifica bitmask LLDP System Capabilities (IEEE 802.1AB)
    private func decodeLLDPCapabilities(_ caps: UInt16) -> [String] {
        var result: [String] = []
        if caps & 0x0001 != 0 { result.append("Other") }
        if caps & 0x0002 != 0 { result.append("Repeater") }
        if caps & 0x0004 != 0 { result.append("Bridge") }
        if caps & 0x0008 != 0 { result.append("WLAN AP") }
        if caps & 0x0010 != 0 { result.append("Router") }
        if caps & 0x0020 != 0 { result.append("Telephone") }
        if caps & 0x0040 != 0 { result.append("DOCSIS") }
        if caps & 0x0080 != 0 { result.append("Station") }
        return result
    }

    /// Decodifica bitmask CDP Capabilities
    private func decodeCDPCapabilities(_ caps: UInt32) -> [String] {
        var result: [String] = []
        if caps & 0x01 != 0 { result.append("Router") }
        if caps & 0x02 != 0 { result.append("Bridge") }
        if caps & 0x04 != 0 { result.append("Source Route Bridge") }
        if caps & 0x08 != 0 { result.append("Switch") }
        if caps & 0x10 != 0 { result.append("Host") }
        if caps & 0x20 != 0 { result.append("IGMP") }
        if caps & 0x40 != 0 { result.append("Repeater") }
        if caps & 0x80 != 0 { result.append("VoIP Phone") }
        return result
    }
}
