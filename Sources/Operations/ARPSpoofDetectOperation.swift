//
//  ARPSpoofDetectOperation.swift
//  HelperDaemon
//
//  Operazione di rilevamento ARP spoofing/MITM tramite pcap.
//  Monitora ARP reply in tempo reale catturando ogni singolo pacchetto.
//  Mantiene mappa IP→MAC pre-seedata con il gateway e rileva:
//  (a) MAC diverso per gateway IP (gateway_spoof)
//  (b) IP con MAC multipli (duplicate_ip)
//  (c) MAC flip rapidi <10s (mac_flip)
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//

import Foundation
import os

class ARPSpoofDetectOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    // MARK: - Risultato

    struct ARPSpoofAlert: Codable {
        let type: String          // "gateway_spoof", "duplicate_ip", "mac_flip"
        let ip: String
        let legitimateMAC: String
        let spoofMAC: String
        let timestamp: Double     // secondi dal 1970
        let packetCount: Int
    }

    // MARK: - Stato Interno

    /// Entry nella mappa IP→MAC con tracking temporale
    private struct MACEntry {
        var mac: String
        var lastSeen: Date
        var count: Int
    }

    // MARK: - Esecuzione

    /// Monitora ARP reply per la durata specificata e rileva tentativi di spoofing.
    func execute(interfaceName: String, durationSeconds: Int32,
                 gatewayIP: String, gatewayMAC: String) -> Result<Data, Error> {

        // Filtro BPF: solo ARP reply (opcode 2)
        let bpfFilter = "arp[6:2] = 2"

        // Apri pcap in modalità non-promiscua
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 128, 0, 100, &errbuf)
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("pcap_open_live ARP spoof detection fallito: \(errMsg)"))
        }
        self.pcapHandle = pcap

        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        // Imposta filtro BPF
        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            HelperLogger.forwardWarning(category: "Operations", message: "Impossibile impostare filtro BPF: \(bpfFilter)", tag: "[ARPSpoof]")
        }

        // Mappa IP→MAC con entry temporali. Pre-seed con il gateway legittimo.
        // Normalizza il MAC gateway nel formato zero-padded identico a PacketBuilder.formatMAC
        // (es. "10:6:45:b3:71:f6" → "10:06:45:B3:71:F6"). Solo .uppercased() non basta:
        // macOS arp -an emette ottetti a singola cifra che causano mismatch con il formato pcap.
        let gwParts = gatewayMAC.split(separator: ":").map(String.init)
        let normalizedGatewayMAC: String
        if gwParts.count == 6 {
            normalizedGatewayMAC = gwParts.map { part in
                let upper = part.uppercased()
                return upper.count == 1 ? "0\(upper)" : upper
            }.joined(separator: ":")
        } else {
            normalizedGatewayMAC = gatewayMAC.uppercased()
        }
        var ipMACMap: [String: MACEntry] = [
            gatewayIP: MACEntry(mac: normalizedGatewayMAC, lastSeen: Date(), count: 0)
        ]

        // Storico: per ogni IP, lista di (MAC, timestamp) per rilevare flip
        var ipMACHistory: [String: [(mac: String, time: Date)]] = [:]

        var alerts: [ARPSpoofAlert] = []
        let deadline = Date().addingTimeInterval(Double(durationSeconds))

        HelperLogger.operations.info("[ARPSpoof] Detection avviato su \(interfaceName), gateway: \(gatewayIP) [\(normalizedGatewayMAC)], durata: \(durationSeconds)s")

        while Date() < deadline && !isCancelled {
            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length >= 42 {
                let buffer = UnsafeBufferPointer(start: packet.data, count: Int(packet.length))

                // Verifica EtherType ARP (0x0806)
                guard buffer[12] == 0x08, buffer[13] == 0x06 else { continue }
                // ARP opcode reply (offset 20-21)
                guard buffer[20] == 0x00, buffer[21] == 0x02 else { continue }

                // Sender MAC (offset 22-27)
                let senderMAC = [buffer[22], buffer[23], buffer[24], buffer[25], buffer[26], buffer[27]]
                let macStr = PacketBuilder.formatMAC(senderMAC)

                // Sender IP (offset 28-31)
                let senderIP = "\(buffer[28]).\(buffer[29]).\(buffer[30]).\(buffer[31])"

                // Ignora broadcast e incompleti
                guard macStr != "FF:FF:FF:FF:FF:FF",
                      macStr != "00:00:00:00:00:00" else { continue }

                let now = Date()

                // Registra nello storico
                var history = ipMACHistory[senderIP] ?? []
                history.append((mac: macStr, time: now))
                // Mantieni solo ultimi 60 secondi di storico
                history = history.filter { now.timeIntervalSince($0.time) < 60 }
                ipMACHistory[senderIP] = history

                if let existing = ipMACMap[senderIP] {
                    if existing.mac != macStr {
                        // (a) Gateway spoof: MAC diverso per il gateway IP
                        if senderIP == gatewayIP {
                            let alert = ARPSpoofAlert(
                                type: "gateway_spoof",
                                ip: senderIP,
                                legitimateMAC: normalizedGatewayMAC,
                                spoofMAC: macStr,
                                timestamp: now.timeIntervalSince1970,
                                packetCount: existing.count + 1
                            )
                            alerts.append(alert)
                            HelperLogger.forwardWarning(category: "Operations", message: "Gateway \(senderIP) MAC cambiato da \(normalizedGatewayMAC) a \(macStr)", tag: "[ARPSpoof]")
                        }

                        // (b) Duplicate IP: IP visto con MAC multipli
                        let alert = ARPSpoofAlert(
                            type: "duplicate_ip",
                            ip: senderIP,
                            legitimateMAC: existing.mac,
                            spoofMAC: macStr,
                            timestamp: now.timeIntervalSince1970,
                            packetCount: existing.count + 1
                        )
                        alerts.append(alert)

                        // (c) MAC flip: cambio MAC rapido (<10s)
                        let recentChanges = history.filter { now.timeIntervalSince($0.time) < 10 }
                        let uniqueMACs = Set(recentChanges.map(\.mac))
                        if uniqueMACs.count >= 3 {
                            let flipAlert = ARPSpoofAlert(
                                type: "mac_flip",
                                ip: senderIP,
                                legitimateMAC: existing.mac,
                                spoofMAC: macStr,
                                timestamp: now.timeIntervalSince1970,
                                packetCount: recentChanges.count
                            )
                            alerts.append(flipAlert)
                            HelperLogger.forwardWarning(category: "Operations", message: "MAC FLIP: IP \(senderIP) ha \(uniqueMACs.count) MAC diversi in <10s", tag: "[ARPSpoof]")
                        }

                        // Aggiorna la mappa con il MAC più recente
                        ipMACMap[senderIP] = MACEntry(mac: macStr, lastSeen: now, count: existing.count + 1)
                    } else {
                        // Stesso MAC: aggiorna timestamp e conteggio
                        ipMACMap[senderIP] = MACEntry(mac: macStr, lastSeen: now, count: existing.count + 1)
                    }
                } else {
                    // Nuovo IP: registra nella mappa
                    ipMACMap[senderIP] = MACEntry(mac: macStr, lastSeen: now, count: 1)
                }
            } else if result == -1 {
                break
            }
        }

        HelperLogger.operations.info("[ARPSpoof] Detection completato: \(ipMACMap.count) IP monitorati, \(alerts.count) alert generati")

        do {
            let jsonData = try JSONEncoder().encode(alerts)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione ARP spoof detection fallita: \(error)"))
        }
    }
}
