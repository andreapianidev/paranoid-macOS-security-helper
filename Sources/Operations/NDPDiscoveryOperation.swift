//
//  NDPDiscoveryOperation.swift
//  HelperDaemon
//
//  Operazione NDP (IPv6 Neighbor Discovery Protocol).
//  Invia ping6 multicast a ff02::1 (all-nodes link-local) per popolare
//  la tabella NDP del kernel, poi legge ndp -an per raccogliere i neighbor.
//  Ritorna [{ipv6, mac, isLinkLocal, isRouter}] come JSON Data.
//

import Foundation
import os

class NDPDiscoveryOperation: BaseOperation {

    private var activeProcess: Process?

    override func cancel() {
        super.cancel()
        activeProcess?.terminate()
    }

    /// Esegue la discovery NDP sull'interfaccia specificata
    func execute(interfaceName: String, timeoutSeconds: Int32) -> Result<Data, Error> {

        guard !isCancelled else { return .failure(HelperError.cancelled) }

        // Fase 1: Popola la tabella NDP con ping6 multicast a ff02::1
        // ff02::1 = all-nodes link-local — ogni dispositivo IPv6 sulla LAN DEVE rispondere
        let pingResult = sendMulticastPing6(interfaceName: interfaceName, timeoutSeconds: timeoutSeconds)
        if case .failure(let error) = pingResult {
            HelperLogger.operations.info("[NDP] NDP ping6 multicast warning: \(error.localizedDescription) — proseguo con ndp -an")
        }

        guard !isCancelled else { return .failure(HelperError.cancelled) }

        // Piccola pausa per permettere al kernel di aggiornare la tabella NDP
        usleep(500_000) // 500ms

        // Fase 2: Leggi la tabella NDP completa
        return readNDPTable(interfaceName: interfaceName)
    }

    // MARK: - Ping6 Multicast

    /// Invia ICMPv6 Echo Request a ff02::1%interfaceName per triggerare Neighbor Solicitation
    private func sendMulticastPing6(interfaceName: String, timeoutSeconds: Int32) -> Result<Void, Error> {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/ping6")
        // -c 3: invia 3 pacchetti (sufficiente per popolare NDP)
        // -W: timeout in ms per risposta (1000ms)
        // -I: forza interfaccia specifica
        // ff02::1: all-nodes link-local multicast
        process.arguments = ["-c", "3", "-W", "1000", "-I", interfaceName, "ff02::1"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        activeProcess = process
        defer { activeProcess = nil }

        do {
            try process.run()
            // Attendi con timeout
            let deadline = Date().addingTimeInterval(Double(timeoutSeconds))
            while process.isRunning && Date() < deadline && !isCancelled {
                usleep(100_000) // 100ms
            }
            if process.isRunning {
                process.terminate()
            }
            HelperLogger.operations.info("[NDP] NDP ping6 ff02::1%%\(interfaceName) completato")
            return .success(())
        } catch {
            return .failure(HelperError.operationFailed("ping6 multicast fallito: \(error.localizedDescription)"))
        }
    }

    // MARK: - Parsing tabella NDP

    /// Legge e parsa la tabella NDP del sistema tramite ndp -an
    private func readNDPTable(interfaceName: String) -> Result<Data, Error> {
        let process = Process()
        let pipe = Pipe()
        let stderrPipe = Pipe()

        process.executableURL = URL(fileURLWithPath: "/usr/sbin/ndp")
        process.arguments = ["-an"]
        process.standardOutput = pipe
        process.standardError = stderrPipe

        activeProcess = process
        defer { activeProcess = nil }

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return .failure(HelperError.operationFailed("ndp -an fallito: \(error.localizedDescription)"))
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else {
            return .failure(HelperError.operationFailed("Output ndp -an non leggibile"))
        }

        let neighbors = parseNDPOutput(output, interfaceName: interfaceName)

        do {
            let jsonData = try JSONSerialization.data(withJSONObject: neighbors)
            HelperLogger.operations.info("[NDP] NDP discovery completata: \(neighbors.count) neighbor trovati su \(interfaceName)")
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione JSON NDP fallita: \(error)"))
        }
    }

    /// Parsa l'output di ndp -an in array di dizionari.
    ///
    /// Formato tipico macOS:
    /// ```
    /// Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs
    /// fe80::1%en0                     aa:bb:cc:dd:ee:ff  en0   23h51m49s S  R
    /// fe80::aede:48ff:fe00:1122%en0   ae:de:48:00:11:22  en0   permanent R
    /// 2001:db8::1                     00:11:22:33:44:55  en0   23h50m12s S  R
    /// ```
    private func parseNDPOutput(_ output: String, interfaceName: String) -> [[String: Any]] {
        var results: [[String: Any]] = []
        var seenMACs: Set<String> = []

        let lines = output.components(separatedBy: "\n")

        for line in lines {
            // Salta header e righe vuote
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("Neighbor") { continue }

            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            // Formato minimo: ipv6 mac interface [expire] [state] [flags]
            guard parts.count >= 3 else { continue }

            var ipv6 = parts[0]
            let macRaw = parts[1]
            let netif = parts[2]

            // Filtra per interfaccia richiesta
            guard netif == interfaceName else { continue }

            // Salta entry incomplete (MAC "(incomplete)" o assente)
            guard macRaw.contains(":") && macRaw.count >= 11 else { continue }

            // Normalizza MAC: converti in formato AA:BB:CC:DD:EE:FF
            let normalizedMAC = normalizeMAC(macRaw)
            guard !normalizedMAC.isEmpty else { continue }

            // Ignora MAC broadcast e zero
            if normalizedMAC == "FF:FF:FF:FF:FF:FF" || normalizedMAC == "00:00:00:00:00:00" { continue }
            // Ignora multicast MAC (bit 0 del primo byte = 1, eccetto broadcast)
            if let firstByte = UInt8(normalizedMAC.prefix(2), radix: 16), firstByte & 0x01 != 0 { continue }

            // Rimuovi il suffisso %interfaccia dall'IPv6
            if let percentIndex = ipv6.firstIndex(of: "%") {
                ipv6 = String(ipv6[ipv6.startIndex..<percentIndex])
            }

            // Determina se è link-local (fe80::/10)
            let isLinkLocal = ipv6.lowercased().hasPrefix("fe80")

            // Determina se è router (flag "R" nelle colonne flags)
            // Le flags sono tipicamente nella 6a colonna (index 5) o successive
            var isRouter = false
            if parts.count >= 6 {
                // Cerca "R" nelle colonne dopo expire/state
                for i in 4..<parts.count {
                    if parts[i] == "R" || parts[i].contains("R") {
                        isRouter = true
                        break
                    }
                }
            }

            // Deduplicazione per MAC: preferisci indirizzo global su link-local
            if seenMACs.contains(normalizedMAC) {
                // Se questo è global e l'esistente era link-local, sostituisci
                if !isLinkLocal, let existingIndex = results.firstIndex(where: {
                    ($0["mac"] as? String) == normalizedMAC && ($0["isLinkLocal"] as? Bool) == true
                }) {
                    // Salva il link-local come campo aggiuntivo
                    var updated = results[existingIndex]
                    updated["linkLocalAddress"] = results[existingIndex]["ipv6"]
                    updated["ipv6"] = ipv6
                    updated["isLinkLocal"] = false
                    if isRouter { updated["isRouter"] = true }
                    results[existingIndex] = updated
                    continue
                }
                // Aggiungi comunque se è un indirizzo diverso dallo stesso MAC
                // (un host può avere più IPv6: link-local + global + privacy)
            }
            seenMACs.insert(normalizedMAC)

            var entry: [String: Any] = [
                "ipv6": ipv6,
                "mac": normalizedMAC,
                "isLinkLocal": isLinkLocal,
                "isRouter": isRouter
            ]

            // Se è global, cerca anche il link-local dello stesso MAC per completezza
            if !isLinkLocal {
                entry["linkLocalAddress"] = NSNull()
            }

            results.append(entry)
        }

        return results
    }

    // MARK: - Utility

    /// Normalizza un MAC address in formato AA:BB:CC:DD:EE:FF
    /// ndp può restituire ottetti a singola cifra (es. "0:11:22:33:44:55")
    private func normalizeMAC(_ raw: String) -> String {
        let cleaned = raw.replacingOccurrences(of: "-", with: ":").uppercased()
        let octets = cleaned.split(separator: ":").map(String.init)

        // ndp su macOS a volte emette ottetti senza zero-padding (es. "0:11:22:33:44:55")
        guard octets.count == 6 else { return "" }

        let padded = octets.map { octet -> String in
            if octet.count == 1 {
                return "0\(octet)"
            }
            return octet
        }

        return padded.joined(separator: ":")
    }
}
