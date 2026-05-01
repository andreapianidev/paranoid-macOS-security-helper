//
//  ARPScanOperation.swift
//  HelperDaemon
//
//  Operazione ARP scan usando libpcap.
//  Apre l'interfaccia, imposta filtro BPF per ARP reply,
//  invia ARP request per ogni IP nel range, raccoglie risposte.
//  Ritorna [{ip, mac}] come JSON Data.
//

import Foundation
import os

class ARPScanOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    /// Esegue l'ARP scan sul range IP specificato
    func execute(interfaceName: String, startIP: String, endIP: String,
                 timeoutMs: Int32) -> Result<Data, Error> {

        guard let srcMAC = PacketBuilder.getInterfaceMAC(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere MAC di \(interfaceName)"))
        }
        guard let srcIPStr = PacketBuilder.getInterfaceIP(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere IP di \(interfaceName)"))
        }

        let srcIP = PacketBuilder.ipToUInt32(srcIPStr)
        let ips = PacketBuilder.generateIPRange(start: startIP, end: endIP)
        guard !ips.isEmpty else {
            return .failure(HelperError.invalidParameters("Range IP non valido: \(startIP) - \(endIP)"))
        }

        // Apri pcap
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 128, 0, Int32(min(timeoutMs, 100)), &errbuf)
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

        // Filtro BPF: solo ARP reply
        let filterResult = "arp[6:2] = 2".withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            return .failure(HelperError.pcapError("Impossibile impostare filtro BPF ARP"))
        }

        // Risultati
        var results: [[String: String]] = []
        let resultsLock = NSLock()

        // Timing per diagnostica
        let scanStartTime = Date()
        var pass1Duration: Double = 0
        var pass1Count: Int = 0
        var pass2Duration: Double = 0
        var pass2Count: Int = 0
        var pass3Duration: Double = 0
        var pass3Count: Int = 0

        // Invia ARP request per ogni IP
        for ipStr in ips {
            guard !isCancelled else {
                return .failure(HelperError.cancelled)
            }

            let dstIP = PacketBuilder.ipToUInt32(ipStr)
            let frame = PacketBuilder.buildARPRequest(srcMAC: srcMAC, srcIP: srcIP, dstIP: dstIP)

            frame.withUnsafeBytes { buffer in
                guard let ptr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                pcap_bridge_send_packet(pcap, ptr, Int32(frame.count))
            }

            // Pausa tra i pacchetti — 1.5ms per dare tempo ai WiFi extender/bridge
            // di inoltrare ogni ARP request ai client sull'altro segmento wireless
            usleep(1500)
        }

        // Raccogli risposte per il timeout specificato
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)

        while Date() < deadline && !isCancelled {
            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length >= 42 {
                parseARPReply(packet: &packet, results: &results, resultsLock: resultsLock)
            } else if result == -1 {
                break // Errore
            }
            // result == 0 → timeout, continua
        }

        pass1Duration = Date().timeIntervalSince(scanStartTime) * 1000.0
        pass1Count = results.count

        // Retry pass: re-invia ARP request solo per IP che non hanno risposto
        // Host con ARP cold cache hanno ~50% packet loss sul primo pacchetto
        if !isCancelled {
            let firstRoundCount = results.count
            let respondedIPs = Set(results.compactMap { $0["ip"] })
            let missingIPs = ips.filter { !respondedIPs.contains($0) }

            if !missingIPs.isEmpty {
                HelperLogger.operations.info("[ARP] Retry: \(missingIPs.count)/\(ips.count) IP non hanno risposto al primo round, invio secondo round")

                for ipStr in missingIPs {
                    guard !isCancelled else { break }

                    let dstIP = PacketBuilder.ipToUInt32(ipStr)
                    let frame = PacketBuilder.buildARPRequest(srcMAC: srcMAC, srcIP: srcIP, dstIP: dstIP)
                    frame.withUnsafeBytes { buffer in
                        guard let ptr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                        pcap_bridge_send_packet(pcap, ptr, Int32(frame.count))
                    }
                    usleep(1000) // 1ms — più lento per host dietro bridge/extender
                }

                // Raccogli risposte del retry (1.5s per host dietro bridge wireless)
                let retryDeadline = Date().addingTimeInterval(1.5)
                while Date() < retryDeadline && !isCancelled {
                    var packet = pcap_packet_t()
                    let result = pcap_bridge_next_packet(pcap, &packet)
                    if result == 1 && packet.length >= 42 {
                        parseARPReply(packet: &packet, results: &results, resultsLock: resultsLock)
                    } else if result == -1 {
                        break
                    }
                }

                let retryFound = results.count - firstRoundCount
                if retryFound > 0 {
                    HelperLogger.operations.info("[ARP] Retry recuperati: \(retryFound) host aggiuntivi (cold cache)")
                } else {
                    HelperLogger.operations.info("[ARP] Retry completato: nessun host aggiuntivo trovato — \(missingIPs.count) IP effettivamente offline")
                }
            }
        }

        pass2Duration = Date().timeIntervalSince(scanStartTime) * 1000.0
        pass2Count = results.count - pass1Count

        // Pass 3: bridge/extender recovery — ritmo molto conservativo per host
        // dietro WiFi extender che non hanno risposto nei primi due round
        if !isCancelled {
            let prePass3Count = results.count
            let respondedIPs2 = Set(results.compactMap { $0["ip"] })
            let missingIPs2 = ips.filter { !respondedIPs2.contains($0) }

            if !missingIPs2.isEmpty {
                HelperLogger.operations.info("[ARP] Pass 3 (bridge recovery): \(missingIPs2.count) IP ancora mancanti, invio terzo round conservativo")

                for ipStr in missingIPs2 {
                    guard !isCancelled else { break }

                    let dstIP = PacketBuilder.ipToUInt32(ipStr)
                    let frame = PacketBuilder.buildARPRequest(srcMAC: srcMAC, srcIP: srcIP, dstIP: dstIP)
                    frame.withUnsafeBytes { buffer in
                        guard let ptr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                        pcap_bridge_send_packet(pcap, ptr, Int32(frame.count))
                    }
                    usleep(2000) // 2ms — molto conservativo per bridge wireless
                }

                // Raccogli risposte (1s timeout)
                let pass3Deadline = Date().addingTimeInterval(1.0)
                while Date() < pass3Deadline && !isCancelled {
                    var packet = pcap_packet_t()
                    let result = pcap_bridge_next_packet(pcap, &packet)
                    if result == 1 && packet.length >= 42 {
                        parseARPReply(packet: &packet, results: &results, resultsLock: resultsLock)
                    } else if result == -1 {
                        break
                    }
                }

                let pass3Found = results.count - prePass3Count
                pass3Count = pass3Found
                if pass3Found > 0 {
                    HelperLogger.operations.info("[ARP] Pass 3 recuperati: \(pass3Found) host aggiuntivi (bridge/extender)")
                }
            }
        }

        pass3Duration = Date().timeIntervalSince(scanStartTime) * 1000.0

        // Serializza risultati con metadata diagnostica
        let totalDuration = Date().timeIntervalSince(scanStartTime) * 1000.0
        HelperLogger.operations.info("[ARP] Scan completato: \(results.count) host su \(interfaceName) in \(String(format: "%.0f", totalDuration))ms — pass1: \(pass1Count) (\(String(format: "%.0f", pass1Duration))ms), pass2: +\(pass2Count) (\(String(format: "%.0f", pass2Duration))ms), pass3: +\(pass3Count) (\(String(format: "%.0f", pass3Duration))ms)")

        do {
            let jsonData = try JSONSerialization.data(withJSONObject: results)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione JSON fallita: \(error)"))
        }
    }

    // MARK: - Parsing ARP Reply

    /// Parsa un ARP reply e aggiunge il risultato se valido e non duplicato
    private func parseARPReply(packet: inout pcap_packet_t,
                                results: inout [[String: String]],
                                resultsLock: NSLock) {
        let data = UnsafeBufferPointer(start: packet.data, count: Int(packet.length))

        // Verifica EtherType ARP (0x0806)
        guard data.count >= 42,
              data[12] == 0x08, data[13] == 0x06 else { return }

        // ARP opcode reply (offset 20-21 nel frame, 6-7 nell'ARP header)
        guard data[20] == 0x00, data[21] == 0x02 else { return }

        // Sender MAC (offset 22-27)
        let mac = [data[22], data[23], data[24], data[25], data[26], data[27]]
        let macStr = PacketBuilder.formatMAC(mac)

        // Sender IP (offset 28-31)
        let ipBytes = [data[28], data[29], data[30], data[31]]
        let ipStr = "\(ipBytes[0]).\(ipBytes[1]).\(ipBytes[2]).\(ipBytes[3])"

        // Ignora broadcast e incompleti
        guard macStr != "FF:FF:FF:FF:FF:FF",
              macStr != "00:00:00:00:00:00" else { return }

        resultsLock.lock()
        // Evita duplicati
        if !results.contains(where: { $0["ip"] == ipStr }) {
            results.append(["ip": ipStr, "mac": macStr])
        }
        resultsLock.unlock()
    }
}
