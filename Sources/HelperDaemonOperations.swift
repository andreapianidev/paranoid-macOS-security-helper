//
//  HelperDaemonOperations.swift
//  HelperDaemon
//
//  Implementazione del protocollo PrivilegedHelperProtocol.
//  Delega le operazioni effettive alle classi Operation specifiche.
//  Gestisce cancellazione e tracking operazioni in corso.
//

import Foundation
import os

class HelperDaemonOperations: NSObject, PrivilegedHelperProtocol {

    /// Operazioni in corso, indicizzate per operationId
    private var activeOperations: [String: Any] = [:]
    /// Timestamp avvio per calcolo durata
    private var operationStartTimes: [String: Date] = [:]
    private let operationsLock = NSLock()

    /// Timeout globale di default per operazioni (5 minuti)
    private static let defaultTimeoutSeconds: Int = 300

    // MARK: - Validazione Input

    /// Regex per nomi interfaccia BSD validi (es. "en0", "utun3")
    private static let interfaceNameRegex = try! NSRegularExpression(pattern: "^[a-zA-Z0-9]+$")

    /// Valida il nome interfaccia contro injection. Ritorna errore se non valido.
    private func validateInterfaceName(_ name: String) -> HelperError? {
        let range = NSRange(name.startIndex..., in: name)
        if Self.interfaceNameRegex.firstMatch(in: name, range: range) == nil {
            return .invalidParameters("Nome interfaccia non valido: \(name)")
        }
        return nil
    }

    // MARK: - Esecuzione Generica con Watchdog

    /// Esegue un'operazione con tracking, watchdog timeout, e gestione risultato.
    /// - Parameters:
    ///   - operation: L'operazione da eseguire
    ///   - id: Identificatore univoco per tracking/cancellazione
    ///   - timeoutSeconds: Timeout massimo (default 300s). 0 = nessun watchdog.
    ///   - execute: Closure che esegue l'operazione e ritorna Result
    ///   - reply: Callback XPC per il risultato
    private func runOperation<T: CancellableOperation>(
        _ operation: T, id: String,
        timeoutSeconds: Int = HelperDaemonOperations.defaultTimeoutSeconds,
        execute: @escaping (T) -> Result<Data, Error>,
        reply: @escaping (Data?, Error?) -> Void
    ) {
        trackOperation(operation, id: id)

        // Flag per garantire che reply sia chiamato una sola volta
        let replied = NSLock()
        var hasReplied = false

        let safeReply: (Data?, Error?) -> Void = { data, error in
            replied.lock()
            guard !hasReplied else { replied.unlock(); return }
            hasReplied = true
            replied.unlock()
            reply(data, error)
        }

        // Watchdog: forza cancellazione e reply se l'operazione sfora il timeout
        var watchdog: DispatchWorkItem?
        if timeoutSeconds > 0 {
            let wd = DispatchWorkItem { [weak self] in
                HelperLogger.forwardWarning(category: "Operations", message: "Watchdog timeout (\(timeoutSeconds)s) per operazione \(id)")
                self?.cancelOperation(operationId: id)
                safeReply(nil, HelperError.timeout("Timeout globale (\(timeoutSeconds)s) superato"))
            }
            watchdog = wd
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + .seconds(timeoutSeconds), execute: wd
            )
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = execute(operation)
            watchdog?.cancel()
            self?.removeOperation(id: id)

            switch result {
            case .success(let data):
                safeReply(data, nil)
            case .failure(let error):
                safeReply(nil, error)
            }
        }
    }

    // MARK: - Stato Helper

    func ping(withReply reply: @escaping (Bool) -> Void) {
        reply(true)
    }

    func getVersion(withReply reply: @escaping (String) -> Void) {
        reply(HelperConstants.helperVersion)
    }

    // MARK: - ARP Scan

    func scanARP(interfaceName: String, startIP: String, endIP: String,
                 timeoutMs: Int32, operationId: String,
                 withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(ARPScanOperation(), id: operationId) { op in
            op.execute(interfaceName: interfaceName, startIP: startIP,
                       endIP: endIP, timeoutMs: timeoutMs)
        } reply: { reply($0, $1) }
    }

    // MARK: - SYN Scan

    func scanSYN(targetIP: String, ports: Data, interfaceName: String,
                 timeoutMs: Int32, maxConcurrent: Int32, operationId: String,
                 withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }
        guard let portList = try? JSONDecoder().decode([Int32].self, from: ports) else {
            reply(nil, HelperError.invalidParameters("Impossibile decodificare lista porte"))
            return
        }

        runOperation(SYNScanOperation(), id: operationId) { op in
            op.execute(targetIP: targetIP, ports: portList,
                       interfaceName: interfaceName, timeoutMs: timeoutMs,
                       maxConcurrent: maxConcurrent)
        } reply: { reply($0, $1) }
    }

    // MARK: - UDP Scan

    func scanUDP(targetIP: String, ports: Data, interfaceName: String,
                 timeoutMs: Int32, operationId: String,
                 withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }
        guard let portList = try? JSONDecoder().decode([Int32].self, from: ports) else {
            reply(nil, HelperError.invalidParameters("Impossibile decodificare lista porte"))
            return
        }

        runOperation(UDPScanOperation(), id: operationId) { op in
            op.execute(targetIP: targetIP, ports: portList,
                       interfaceName: interfaceName, timeoutMs: timeoutMs)
        } reply: { reply($0, $1) }
    }

    // MARK: - ICMP Ping

    func pingICMP(targetIP: String, count: Int32, timeoutMs: Int32,
                  interfaceName: String, operationId: String,
                  withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(ICMPPingOperation(), id: operationId, timeoutSeconds: 60) { op in
            op.execute(targetIP: targetIP, count: count,
                       timeoutMs: timeoutMs, interfaceName: interfaceName)
        } reply: { reply($0, $1) }
    }

    // MARK: - Passive Discovery

    func passiveDiscovery(interfaceName: String, durationSeconds: Int32,
                          filterTypes: Data, operationId: String,
                          withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }
        let filters = (try? JSONDecoder().decode([String].self, from: filterTypes)) ?? []

        runOperation(PassiveCaptureOperation(), id: operationId,
                     timeoutSeconds: Int(durationSeconds) + 30) { op in
            op.execute(interfaceName: interfaceName, durationSeconds: durationSeconds,
                       filterTypes: filters)
        } reply: { reply($0, $1) }
    }

    // MARK: - TCP Fingerprint (SYN-ACK)

    func captureSYNACK(targetIP: String, port: Int32, interfaceName: String,
                       timeoutMs: Int32, operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(SYNScanOperation(), id: operationId, timeoutSeconds: 30) { op in
            op.captureSYNACK(targetIP: targetIP, port: port,
                             interfaceName: interfaceName, timeoutMs: timeoutMs)
        } reply: { reply($0, $1) }
    }

    // MARK: - SYN Monitor (IDS)

    func monitorIncomingSYN(interfaceName: String, durationSeconds: Int32,
                            localIP: String, portThreshold: Int32,
                            operationId: String,
                            withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(SYNMonitorOperation(), id: operationId,
                     timeoutSeconds: Int(durationSeconds) + 30) { op in
            op.execute(interfaceName: interfaceName, durationSeconds: durationSeconds,
                       localIP: localIP, portThreshold: portThreshold)
        } reply: { reply($0, $1) }
    }

    // MARK: - NDP Discovery (IPv6 Neighbor)

    func discoverNDP(interfaceName: String, timeoutSeconds: Int32,
                     operationId: String,
                     withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(NDPDiscoveryOperation(), id: operationId,
                     timeoutSeconds: Int(timeoutSeconds) + 30) { op in
            op.execute(interfaceName: interfaceName, timeoutSeconds: timeoutSeconds)
        } reply: { reply($0, $1) }
    }

    // MARK: - ARP Spoof Detection

    func detectARPSpoof(interfaceName: String, durationSeconds: Int32,
                        gatewayIP: String, gatewayMAC: String,
                        operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(ARPSpoofDetectOperation(), id: operationId,
                     timeoutSeconds: Int(durationSeconds) + 30) { op in
            op.execute(interfaceName: interfaceName, durationSeconds: durationSeconds,
                       gatewayIP: gatewayIP, gatewayMAC: gatewayMAC)
        } reply: { reply($0, $1) }
    }

    // MARK: - Wake-on-LAN

    func sendWakeOnLAN(interfaceName: String, targetMAC: String,
                       operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(WakeOnLANOperation(), id: operationId, timeoutSeconds: 10) { op in
            op.execute(interfaceName: interfaceName, targetMAC: targetMAC)
        } reply: { reply($0, $1) }
    }

    // MARK: - ICMP Traceroute

    func tracerouteICMP(targetIP: String, maxHops: Int32, timeoutMs: Int32,
                        count: Int32, interfaceName: String,
                        operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(ICMPTracerouteOperation(), id: operationId) { op in
            op.execute(targetIP: targetIP, maxHops: maxHops, timeoutMs: timeoutMs,
                       count: count, interfaceName: interfaceName)
        } reply: { reply($0, $1) }
    }

    // MARK: - Rogue DHCP Detection

    func detectRogueDHCP(interfaceName: String, expectedServerIP: String,
                         durationSeconds: Int32, operationId: String,
                         withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(RogueDHCPDetectOperation(), id: operationId,
                     timeoutSeconds: Int(durationSeconds) + 30) { op in
            op.execute(interfaceName: interfaceName, expectedServerIP: expectedServerIP,
                       durationSeconds: durationSeconds)
        } reply: { reply($0, $1) }
    }

    // MARK: - LLDP/CDP Discovery

    func discoverLLDP(interfaceName: String, durationSeconds: Int32,
                      operationId: String,
                      withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(LLDPDiscoveryOperation(), id: operationId,
                     timeoutSeconds: Int(durationSeconds) + 30) { op in
            op.execute(interfaceName: interfaceName, durationSeconds: durationSeconds)
        } reply: { reply($0, $1) }
    }

    // MARK: - HTTP Deep Packet Inspection

    /// Limite massimo body HTTP per prevenire consumo memoria eccessivo (10 MB)
    private static let maxHTTPBodyCap: Int32 = 10 * 1024 * 1024

    func inspectHTTP(interfaceName: String, durationSeconds: Int32,
                     maxBodyBytes: Int32, port: Int32,
                     operationId: String,
                     withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        // Limita maxBodyBytes per prevenire consumo memoria eccessivo
        let safeMaxBody = min(maxBodyBytes, Self.maxHTTPBodyCap)
        if maxBodyBytes > Self.maxHTTPBodyCap {
            HelperLogger.forwardWarning(
                category: "Operations",
                message: "maxBodyBytes \(maxBodyBytes) troncato a \(safeMaxBody) (limite sicurezza)",
                tag: "[HTTP]"
            )
        }

        runOperation(HTTPInspectionOperation(), id: operationId,
                     timeoutSeconds: Int(durationSeconds) + 30) { op in
            op.execute(interfaceName: interfaceName, durationSeconds: durationSeconds,
                       maxBodyBytes: safeMaxBody, port: port)
        } reply: { reply($0, $1) }
    }

    // MARK: - Esecuzione Comandi Generica

    func executeCommand(path: String, arguments: Data, environment: Data?,
                        timeoutSeconds: Int32, outputFile: String,
                        operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void) {
        // Decodifica argomenti
        guard let args = try? JSONDecoder().decode([String].self, from: arguments) else {
            reply(nil, HelperError.invalidParameters("Impossibile decodificare argomenti"))
            return
        }

        // Decodifica environment (opzionale)
        var env: [String: String]?
        if let envData = environment, !envData.isEmpty {
            env = try? JSONDecoder().decode([String: String].self, from: envData)
        }

        let timeout = max(Int(timeoutSeconds), 10) // minimo 10s

        runOperation(CommandExecutionOperation(), id: operationId,
                     timeoutSeconds: timeout + 30) { op in
            op.execute(path: path, arguments: args, environment: env,
                       timeoutSeconds: timeoutSeconds,
                       outputFile: outputFile.isEmpty ? nil : outputFile)
        } reply: { reply($0, $1) }
    }

    // MARK: - 802.11 Monitor Mode

    func startMonitorMode(interfaceName: String, channel: Int32,
                          channelHopping: Bool, durationSeconds: Int32,
                          operationId: String,
                          withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        let timeout = max(Int(durationSeconds), 10)
        runOperation(MonitorModeOperation(), id: operationId,
                     timeoutSeconds: timeout + 60) { op in
            op.execute(interfaceName: interfaceName, channel: channel,
                       channelHopping: channelHopping, durationSeconds: durationSeconds)
        } reply: { reply($0, $1) }
    }

    func stopMonitorMode(operationId: String,
                         withReply reply: @escaping (Data?, Error?) -> Void) {
        cancelOperation(operationId: operationId)
        let result: [String: Bool] = ["stopped": true]
        if let data = try? JSONEncoder().encode(result) {
            reply(data, nil)
        } else {
            reply(nil, nil)
        }
    }

    // MARK: - WPA Handshake Capture

    func captureHandshake(interfaceName: String, targetBSSID: String,
                          channel: Int32, sendDeauth: Bool,
                          clientMAC: String?, durationSeconds: Int32,
                          operationId: String,
                          withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        let timeout = max(Int(durationSeconds), 10)
        runOperation(HandshakeCaptureOperation(), id: operationId,
                     timeoutSeconds: timeout + 60) { op in
            op.execute(interfaceName: interfaceName, targetBSSID: targetBSSID,
                       channel: channel, sendDeauth: sendDeauth,
                       clientMAC: clientMAC, durationSeconds: durationSeconds)
        } reply: { reply($0, $1) }
    }

    // MARK: - Deauth Attack (Pentesting)

    func sendDeauthAttack(interfaceName: String, targetBSSID: String,
                          clientMAC: String, channel: Int32,
                          burstCount: Int32, intervalMs: Int32,
                          reasonCode: Int32, durationSeconds: Int32,
                          operationId: String,
                          withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        let timeout = max(Int(durationSeconds), 10)
        runOperation(DeauthAttackOperation(), id: operationId,
                     timeoutSeconds: timeout + 60) { op in
            op.execute(interfaceName: interfaceName, targetBSSID: targetBSSID,
                       clientMAC: clientMAC, channel: channel,
                       burstCount: burstCount, intervalMs: intervalMs,
                       reasonCode: reasonCode, durationSeconds: durationSeconds)
        } reply: { reply($0, $1) }
    }

    // MARK: - Terminal PTY Session

    func openPTYSession(shellPath: String, arguments: Data, environment: Data,
                        cols: Int32, rows: Int32, outputFile: String,
                        operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void) {
        let args = (try? JSONDecoder().decode([String].self, from: arguments)) ?? []
        let env = (try? JSONDecoder().decode([String: String].self, from: environment)) ?? [:]

        guard !outputFile.isEmpty else {
            reply(nil, HelperError.invalidParameters("outputFile obbligatorio per sessione PTY"))
            return
        }

        let op = PTYSessionOperation()
        // Registriamo SUBITO l'operazione: write/resize/close/cancel arriveranno
        // con lo stesso operationId e devono trovarla in tabella.
        operationsLock.lock()
        activeOperations[operationId] = op
        operationStartTimes[operationId] = Date()
        operationsLock.unlock()
        HelperLogger.operations.info("[PTY] Sessione registrata: \(operationId, privacy: .public)")

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = op.execute(shellPath: shellPath, arguments: args,
                                    environment: env, cols: cols, rows: rows,
                                    outputFile: outputFile)
            switch result {
            case .success(let data):
                reply(data, nil)
                // NON rimuoviamo l'operazione: resta viva fino a close/cancel.
            case .failure(let err):
                self?.operationsLock.lock()
                self?.activeOperations.removeValue(forKey: operationId)
                self?.operationStartTimes.removeValue(forKey: operationId)
                self?.operationsLock.unlock()
                reply(nil, err)
            }
        }
    }

    func writePTYInput(operationId: String, input: Data,
                       withReply reply: @escaping (Data?, Error?) -> Void) {
        operationsLock.lock()
        let op = activeOperations[operationId] as? PTYSessionOperation
        operationsLock.unlock()

        guard let op = op else {
            reply(nil, HelperError.invalidParameters("Sessione PTY non trovata: \(operationId)"))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            switch op.writeInput(input) {
            case .success(let data): reply(data, nil)
            case .failure(let err): reply(nil, err)
            }
        }
    }

    func resizePTYSession(operationId: String, cols: Int32, rows: Int32,
                          withReply reply: @escaping (Bool) -> Void) {
        operationsLock.lock()
        let op = activeOperations[operationId] as? PTYSessionOperation
        operationsLock.unlock()
        guard let op = op else { reply(false); return }
        reply(op.resize(cols: cols, rows: rows))
    }

    func closePTYSession(operationId: String,
                         withReply reply: @escaping (Bool) -> Void) {
        operationsLock.lock()
        let op = activeOperations.removeValue(forKey: operationId) as? PTYSessionOperation
        let start = operationStartTimes.removeValue(forKey: operationId)
        operationsLock.unlock()

        if let op = op {
            op.closeSession()
            if let s = start {
                let durationMs = Date().timeIntervalSince(s) * 1000.0
                HelperLogger.operations.info("[PTY] Sessione \(operationId, privacy: .public) chiusa dopo \(String(format: "%.0f", durationMs), privacy: .public)ms")
            }
            reply(true)
        } else {
            reply(false)
        }
    }

    // MARK: - Cancellazione

    func cancelOperation(operationId: String) {
        operationsLock.lock()
        let operation = activeOperations.removeValue(forKey: operationId) as? CancellableOperation
        let startTime = operationStartTimes.removeValue(forKey: operationId)
        operationsLock.unlock()
        operation?.cancel()

        if let start = startTime {
            let durationMs = Date().timeIntervalSince(start) * 1000.0
            HelperLogger.operations.info("Operazione cancellata: \(operationId, privacy: .public) dopo \(String(format: "%.0f", durationMs), privacy: .public)ms")
        } else {
            HelperLogger.operations.info("Operazione cancellata: \(operationId, privacy: .public)")
        }
    }

    // MARK: - Tracking Operazioni

    private func trackOperation(_ operation: Any, id: String) {
        operationsLock.lock()
        activeOperations[id] = operation
        operationStartTimes[id] = Date()
        operationsLock.unlock()
        HelperLogger.operations.info("Operazione avviata: \(id, privacy: .public)")
    }

    private func removeOperation(id: String) {
        operationsLock.lock()
        activeOperations.removeValue(forKey: id)
        let startTime = operationStartTimes.removeValue(forKey: id)
        operationsLock.unlock()

        if let start = startTime {
            let durationMs = Date().timeIntervalSince(start) * 1000.0
            HelperLogger.operations.info("Operazione completata: \(id, privacy: .public) — durata \(String(format: "%.0f", durationMs), privacy: .public)ms")
        }
    }

    // MARK: - Pcap Port Scan (bypassa pf/VPN kill switch)

    func pcapScanPorts(targetIP: String, ports: Data, interfaceName: String,
                       gatewayMAC: String, timeoutMs: Int32, operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }
        guard let portList = try? JSONDecoder().decode([Int32].self, from: ports) else {
            reply(nil, HelperError.invalidParameters("Impossibile decodificare lista porte"))
            return
        }

        runOperation(PcapSYNScanOperation(), id: operationId) { op in
            op.execute(targetIP: targetIP, ports: portList,
                       interfaceName: interfaceName, gatewayMAC: gatewayMAC,
                       timeoutMs: timeoutMs)
        } reply: { reply($0, $1) }
    }

    // MARK: - Pcap ICMP Ping (bypassa pf/VPN kill switch)

    func pcapPing(targetIP: String, interfaceName: String,
                  gatewayMAC: String, timeoutMs: Int32, count: Int32,
                  operationId: String,
                  withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        runOperation(PcapSYNScanOperation(), id: operationId, timeoutSeconds: 60) { op in
            op.executePing(targetIP: targetIP, interfaceName: interfaceName,
                           gatewayMAC: gatewayMAC, timeoutMs: timeoutMs,
                           count: count)
        } reply: { reply($0, $1) }
    }

    // MARK: - ARP Timing (Camera Locator)

    func scanARPTiming(interfaceName: String, targetIPs: Data, targetMACs: Data,
                       probeCount: Int32, intervalMs: Int32,
                       operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void) {
        if let err = validateInterfaceName(interfaceName) { reply(nil, err); return }

        guard let ips = try? JSONDecoder().decode([String].self, from: targetIPs) else {
            reply(nil, HelperError.invalidParameters("Impossibile decodificare lista IP target"))
            return
        }
        let macs = (try? JSONDecoder().decode([String: String].self, from: targetMACs)) ?? [:]

        // Timeout: probeCount * intervalMs * numero target + margine
        let estimatedSeconds = Int(probeCount) * Int(intervalMs) * ips.count / 1000 + 30
        runOperation(ARPTimingOperation(), id: operationId,
                     timeoutSeconds: estimatedSeconds) { op in
            op.execute(interfaceName: interfaceName, targetIPs: ips,
                       targetMACs: macs, probeCount: probeCount, intervalMs: intervalMs)
        } reply: { reply($0, $1) }
    }

    // MARK: - DNS Bulk Resolve (v2.0)

    func bulkDNSResolve(ips: Data, maxConcurrent: Int32,
                        timeoutPerHost: Int32, operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void) {

        HelperLogger.operations.info("[DNS] bulkDNSResolve richiesto: operationId=\(operationId)")

        guard let ipList = try? JSONDecoder().decode([String].self, from: ips) else {
            reply(nil, HelperError.invalidParameters("Lista IP non valida"))
            return
        }

        guard !ipList.isEmpty else {
            reply(nil, HelperError.invalidParameters("Lista IP vuota"))
            return
        }

        let safeConcurrent = max(1, min(Int(maxConcurrent), 50))
        let safeTimeout = max(1, min(Int(timeoutPerHost), 10))

        HelperLogger.operations.info("[DNS] Bulk resolve: \(ipList.count) IP, concurrency=\(safeConcurrent), timeout/host=\(safeTimeout)s")

        DispatchQueue.global(qos: .userInitiated).async {
            let result = HelperDNSCache.shared.bulkResolve(
                ips: ipList,
                maxConcurrent: safeConcurrent,
                timeoutPerHost: TimeInterval(safeTimeout)
            )

            if result.resolvedCount == 0 && !ipList.isEmpty {
                HelperLogger.forwardInfo(
                    category: "Operations",
                    message: "Bulk DNS: 0/\(ipList.count) risolti — il DNS server locale probabilmente non ha record PTR per la LAN",
                    tag: "[DNS]"
                )
            }

            do {
                let jsonData = try JSONEncoder().encode(result)
                reply(jsonData, nil)
            } catch {
                reply(nil, HelperError.operationFailed("Serializzazione DNS fallita: \(error)"))
            }
        }
    }

    func flushDNSCache(withReply reply: @escaping (Bool) -> Void) {
        HelperDNSCache.shared.flush()
        HelperLogger.operations.info("[DNS] Cache DNS svuotata")
        reply(true)
    }
}

// MARK: - Protocollo Cancellazione

/// Protocollo per operazioni cancellabili
protocol CancellableOperation: AnyObject {
    func cancel()
}

// MARK: - Errori Helper

enum HelperError: LocalizedError {
    case invalidParameters(String)
    case operationFailed(String)
    case pcapError(String)
    case socketError(String)
    case cancelled
    case timeout(String)

    var errorDescription: String? {
        switch self {
        case .invalidParameters(let msg): return "Parametri non validi: \(msg)"
        case .operationFailed(let msg): return "Operazione fallita: \(msg)"
        case .pcapError(let msg): return "Errore pcap: \(msg)"
        case .socketError(let msg): return "Errore socket: \(msg)"
        case .cancelled: return "Operazione cancellata"
        case .timeout(let msg): return "Timeout: \(msg)"
        }
    }
}
