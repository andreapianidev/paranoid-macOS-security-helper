//
//  SYNMonitorOperation.swift
//  HelperDaemon
//
//  Operazione di monitoraggio pacchetti TCP SYN in ingresso tramite BPF/pcap.
//  Cattura SYN puri (flag SYN=1, ACK=0) diretti all'IP locale per rilevare
//  port scan in corso. Aggrega risultati per IP sorgente → porte destinazione.
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//

import Foundation
import os

class SYNMonitorOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    // MARK: - Risultato

    /// Singolo scanner rilevato: IP sorgente che ha colpito N porte distinte
    struct SYNScannerResult: Codable {
        let sourceIP: String
        let ports: [Int]
        let packetCount: Int
    }

    // MARK: - Esecuzione

    /// Monitora SYN in ingresso per la durata specificata e restituisce gli IP
    /// che hanno colpito almeno `portThreshold` porte distinte.
    func execute(interfaceName: String, durationSeconds: Int32,
                 localIP: String, portThreshold: Int32) -> Result<Data, Error> {

        // Filtro BPF: solo pacchetti TCP SYN puri diretti al nostro IP
        // tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn  → SYN=1, ACK=0
        // Esclude SYN-ACK (risposte nostre), RST, e traffico non rilevante
        let bpfFilter = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and dst host \(localIP)"

        // Apri pcap in modalità non-promiscua (catturiamo solo traffico diretto a noi)
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 128, 0, 100, &errbuf) // promisc=0, snaplen=128 (basta per header IP+TCP)
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("pcap_open_live SYN monitor fallito: \(errMsg)"))
        }
        self.pcapHandle = pcap

        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        // Imposta filtro BPF (compilato nel kernel per efficienza)
        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            HelperLogger.forwardWarning(category: "Operations", message: "Impossibile impostare filtro BPF: \(bpfFilter)", tag: "[SYNMonitor]")
            // Continuiamo comunque — filtreremo in software
        }

        // Strutture di aggregazione
        // sourceIP → (set di porte destinazione, conteggio pacchetti totali)
        var scannerMap: [String: (ports: Set<UInt16>, count: Int)] = [:]
        let deadline = Date().addingTimeInterval(Double(durationSeconds))

        HelperLogger.operations.info("[SYNMonitor] SYN monitor avviato su \(interfaceName), IP locale: \(localIP), durata: \(durationSeconds)s, soglia: \(portThreshold) porte")

        while Date() < deadline && !isCancelled {
            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length > 0 {
                // Parsa il pacchetto catturato
                if let (srcIP, dstPort) = parseSYNPacket(data: packet.data, length: Int(packet.length), expectedDstIP: localIP) {
                    var entry = scannerMap[srcIP] ?? (ports: Set<UInt16>(), count: 0)
                    entry.ports.insert(dstPort)
                    entry.count += 1
                    scannerMap[srcIP] = entry
                }
            } else if result == -1 {
                // Errore pcap
                break
            }
            // result == 0 → timeout, loop normale
        }

        // Filtra: solo IP che hanno colpito almeno portThreshold porte distinte
        let scanners: [SYNScannerResult] = scannerMap.compactMap { (ip, data) in
            guard data.ports.count >= Int(portThreshold) else { return nil }
            return SYNScannerResult(
                sourceIP: ip,
                ports: data.ports.sorted().map(Int.init),
                packetCount: data.count
            )
        }.sorted { $0.ports.count > $1.ports.count } // Ordina per numero porte (più aggressivo prima)

        HelperLogger.operations.info("[SYNMonitor] SYN monitor completato: \(scannerMap.count) IP visti, \(scanners.count) scanner rilevati (soglia \(portThreshold) porte)")

        do {
            let jsonData = try JSONEncoder().encode(scanners)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione SYN monitor fallita: \(error)"))
        }
    }

    // MARK: - Parsing Pacchetti

    /// Parsa un pacchetto Ethernet/IPv4/TCP ed estrae IP sorgente e porta destinazione.
    /// Verifica che sia un SYN puro diretto all'IP locale atteso.
    private func parseSYNPacket(data: UnsafePointer<UInt8>, length: Int, expectedDstIP: String) -> (sourceIP: String, dstPort: UInt16)? {
        guard length >= 54 else { return nil } // Ethernet(14) + IP(20) + TCP(20) minimo

        let buffer = UnsafeBufferPointer(start: data, count: length)

        // Ethernet header: 14 byte
        let etherType = (UInt16(buffer[12]) << 8) | UInt16(buffer[13])
        guard etherType == 0x0800 else { return nil } // Solo IPv4

        // IP header
        let ipOffset = 14
        let ipVersion = (buffer[ipOffset] >> 4) & 0x0F
        guard ipVersion == 4 else { return nil }

        let ipHeaderLen = Int(buffer[ipOffset] & 0x0F) * 4
        guard ipHeaderLen >= 20 else { return nil }

        let ipProtocol = buffer[ipOffset + 9]
        guard ipProtocol == 6 else { return nil } // Solo TCP

        // IP sorgente (offset 12-15 dall'inizio header IP)
        let srcIP = "\(buffer[ipOffset + 12]).\(buffer[ipOffset + 13]).\(buffer[ipOffset + 14]).\(buffer[ipOffset + 15])"

        // IP destinazione (offset 16-19) — verifica software aggiuntiva
        let dstIP = "\(buffer[ipOffset + 16]).\(buffer[ipOffset + 17]).\(buffer[ipOffset + 18]).\(buffer[ipOffset + 19])"
        guard dstIP == expectedDstIP else { return nil }

        // Ignora pacchetti dal nostro stesso IP (risposte, loopback)
        guard srcIP != expectedDstIP else { return nil }

        // TCP header
        let tcpOffset = ipOffset + ipHeaderLen
        guard tcpOffset + 14 <= length else { return nil } // Almeno fino ai flag TCP

        let dstPort = (UInt16(buffer[tcpOffset + 2]) << 8) | UInt16(buffer[tcpOffset + 3])
        let tcpFlags = buffer[tcpOffset + 13]

        // Verifica software: SYN=1, ACK=0 (il filtro BPF dovrebbe già filtrare, ma double-check)
        let isSYN = (tcpFlags & UInt8(TCP_FLAG_SYN)) != 0
        let isACK = (tcpFlags & UInt8(TCP_FLAG_ACK)) != 0
        guard isSYN && !isACK else { return nil }

        // Ignora broadcast/multicast source
        guard !srcIP.hasPrefix("224."), !srcIP.hasPrefix("255."), srcIP != "0.0.0.0" else { return nil }

        return (srcIP, dstPort)
    }
}
