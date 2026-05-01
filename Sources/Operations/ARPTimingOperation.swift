//
//  ARPTimingOperation.swift
//  HelperDaemon
//
//  Operazione ARP timing ad alta precisione per localizzazione telecamere.
//  Invia N probe ARP a un singolo target e misura RTT Layer 2 puro.
//  Usa mach_absolute_time() per precisione sub-millisecondo.
//  Ritorna latenze individuali come JSON per analisi statistica lato app.
//

import Foundation
import os

class ARPTimingOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    /// Risultato interno per serializzazione JSON
    private struct TimingResult: Codable {
        let ip: String
        let mac: String
        let latenciesMs: [Double]
        let sent: Int
        let received: Int
    }

    /// Esegue il timing ARP verso i target specificati.
    /// Per ogni IP invia `probeCount` ARP request con `intervalMs` di pausa tra i probe,
    /// misurando il RTT Layer 2 con precisione nanosecondi.
    ///
    /// - Parameters:
    ///   - interfaceName: Interfaccia BSD (es. "en0")
    ///   - targetIPs: Lista IP target (serializzata da JSON [String])
    ///   - targetMACs: Dizionario IP→MAC per filtrare risposte (serializzato da JSON [String:String])
    ///   - probeCount: Numero di probe per target (default 50)
    ///   - intervalMs: Pausa tra probe in millisecondi (default 100)
    func execute(interfaceName: String, targetIPs: [String],
                 targetMACs: [String: String], probeCount: Int32,
                 intervalMs: Int32) -> Result<Data, Error> {

        guard let srcMAC = PacketBuilder.getInterfaceMAC(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere MAC di \(interfaceName)"))
        }
        guard let srcIPStr = PacketBuilder.getInterfaceIP(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere IP di \(interfaceName)"))
        }

        let srcIP = PacketBuilder.ipToUInt32(srcIPStr)

        guard !targetIPs.isEmpty else {
            return .failure(HelperError.invalidParameters("Lista target vuota"))
        }

        // Apri pcap con timeout corto per polling rapido
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 128, 0, 10, &errbuf) // 10ms timeout pcap
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

        // Ottieni mach_absolute_time info per conversione in nanosecondi
        var timebaseInfo = mach_timebase_info_data_t()
        mach_timebase_info(&timebaseInfo)
        let nanosFactor = Double(timebaseInfo.numer) / Double(timebaseInfo.denom)

        // Risultati per ogni target
        var results: [TimingResult] = []
        let probes = Int(probeCount)
        let interval = useconds_t(intervalMs * 1000) // millisecondi → microsecondi

        for targetIP in targetIPs {
            guard !isCancelled else {
                return .failure(HelperError.cancelled)
            }

            let dstIP = PacketBuilder.ipToUInt32(targetIP)
            let frame = PacketBuilder.buildARPRequest(srcMAC: srcMAC, srcIP: srcIP, dstIP: dstIP)

            // MAC target per filtrare le risposte (evita di confondere con ARP di altri host)
            let expectedMAC = targetMACs[targetIP]?.uppercased()

            var latencies: [Double] = []
            var sentCount = 0
            var receivedCount = 0

            for _ in 0..<probes {
                guard !isCancelled else {
                    return .failure(HelperError.cancelled)
                }

                // Timestamp invio (mach_absolute_time = alta precisione)
                let sendTime = mach_absolute_time()

                frame.withUnsafeBytes { buffer in
                    guard let ptr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                    pcap_bridge_send_packet(pcap, ptr, Int32(frame.count))
                }
                sentCount += 1

                // Attendi risposta con timeout di 50ms per singolo probe
                let probeDeadlineNanos = sendTime + UInt64(50_000_000 / nanosFactor) // 50ms

                while mach_absolute_time() < probeDeadlineNanos && !isCancelled {
                    var packet = pcap_packet_t()
                    let result = pcap_bridge_next_packet(pcap, &packet)

                    if result == 1 && packet.length >= 42 {
                        // Timestamp ricezione
                        let recvTime = mach_absolute_time()

                        // Parsa ARP reply: sender IP a offset 28-31, sender MAC a 22-27
                        guard let data = packet.data else { continue }
                        let senderIP = String(format: "%d.%d.%d.%d",
                                              data[28], data[29], data[30], data[31])

                        if senderIP == targetIP {
                            // Verifica MAC se disponibile
                            if let expected = expectedMAC {
                                let replyMAC = String(format: "%02X:%02X:%02X:%02X:%02X:%02X",
                                                      data[22], data[23], data[24],
                                                      data[25], data[26], data[27])
                                guard replyMAC == expected else { continue }
                            }

                            let elapsedNanos = Double(recvTime - sendTime) * nanosFactor
                            let elapsedMs = elapsedNanos / 1_000_000.0
                            latencies.append(elapsedMs)
                            receivedCount += 1
                            break
                        }
                    } else if result == -1 {
                        break // Errore pcap
                    }
                    // result == 0 → timeout pcap, continua polling
                }

                // Pausa tra probe
                if interval > 0 {
                    usleep(interval)
                }
            }

            // Aggiungi risultato anche se nessuna risposta (con latencies vuoto)
            let mac = targetMACs[targetIP] ?? ""
            results.append(TimingResult(
                ip: targetIP,
                mac: mac,
                latenciesMs: latencies,
                sent: sentCount,
                received: receivedCount
            ))

            HelperLogger.operations.info("[ARPTiming] \(targetIP, privacy: .public): \(receivedCount)/\(sentCount) risposte, mediana=\(latencies.sorted().dropFirst(latencies.count / 4).first.map { String(format: "%.3f", $0) } ?? "N/A", privacy: .public)ms")
        }

        // Serializza risultati
        do {
            let jsonData = try JSONEncoder().encode(results)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione JSON fallita: \(error)"))
        }
    }
}
