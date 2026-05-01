//
//  CommandExecutionOperation.swift
//  HelperDaemon
//
//  Operazione per esecuzione generica di comandi shell come root.
//  Usata per tool esterni (nmap, masscan, bettercap) senza richiedere
//  la password admin ogni volta — il daemon gira già come root.
//  Output scritto in file temporaneo per streaming real-time dall'app.
//

import Foundation
import os

class CommandExecutionOperation: BaseOperation {

    /// Processo in esecuzione (per cancellazione)
    private var process: Process?
    private let processLock = NSLock()

    override func cancel() {
        super.cancel()
        processLock.lock()
        let proc = process
        processLock.unlock()
        if let proc = proc, proc.isRunning {
            proc.terminate()
            HelperLogger.operations.info("[CommandExec] Processo terminato per cancellazione")
        }
    }

    // MARK: - Risultato

    struct CommandResult: Codable {
        let stdout: String
        let stderr: String
        let exitCode: Int32
    }

    // MARK: - Validazione

    /// Whitelist di directory da cui è permesso eseguire binari.
    /// Impedisce esecuzione arbitraria di binari da posizioni non sicure.
    /// Include Cellar/opt perché Homebrew usa symlink: /opt/homebrew/bin/nmap → /opt/homebrew/Cellar/nmap/.../bin/nmap
    private static let allowedPrefixes: [String] = [
        "/opt/homebrew/bin/",
        "/opt/homebrew/sbin/",
        "/opt/homebrew/Cellar/",
        "/opt/homebrew/opt/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
        "/usr/local/Cellar/",
        "/usr/local/opt/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/"
    ]

    /// Valida che il path del binario sia in una directory consentita
    private func validatePath(_ path: String) -> HelperError? {
        // Risolvi symlink per evitare bypass
        let resolved = (path as NSString).resolvingSymlinksInPath

        // Verifica che il path sia in una directory consentita
        let isAllowed = Self.allowedPrefixes.contains { prefix in
            resolved.hasPrefix(prefix)
        }

        guard isAllowed else {
            return .invalidParameters("Path non consentito: \(path) (risolto: \(resolved)). Solo binari in /opt/homebrew, /usr/local, /usr, /bin, /sbin sono permessi.")
        }

        // Verifica che il file esista e sia eseguibile
        guard FileManager.default.isExecutableFile(atPath: resolved) else {
            return .invalidParameters("Binario non trovato o non eseguibile: \(resolved)")
        }

        return nil
    }

    // MARK: - Esecuzione

    /// Esegue un comando come root e ritorna stdout, stderr, exitCode.
    /// Se outputFile è specificato, scrive stdout+stderr nel file per streaming real-time.
    func execute(path: String, arguments: [String], environment: [String: String]?,
                 timeoutSeconds: Int32, outputFile: String?) -> Result<Data, Error> {

        // Validazione sicurezza: solo binari da directory consentite
        if let err = validatePath(path) {
            return .failure(err)
        }

        HelperLogger.operations.info("[CommandExec] Esecuzione: \(path) \(arguments.joined(separator: " "))")

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = arguments

        // Configura environment
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
        if let extra = environment {
            for (key, value) in extra {
                env[key] = value
            }
        }
        proc.environment = env

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        proc.standardOutput = stdoutPipe
        proc.standardError = stderrPipe

        // File handle per streaming output (opzionale)
        var outputFileHandle: FileHandle?
        if let outputPath = outputFile, !outputPath.isEmpty {
            FileManager.default.createFile(atPath: outputPath, contents: nil)
            outputFileHandle = FileHandle(forWritingAtPath: outputPath)
        }

        var stdoutData = Data()
        var stderrData = Data()
        let dataLock = NSLock()

        // Lettura incrementale stdout
        stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if !data.isEmpty {
                dataLock.lock()
                stdoutData.append(data)
                dataLock.unlock()
                outputFileHandle?.write(data)
            }
        }

        // Lettura incrementale stderr
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if !data.isEmpty {
                dataLock.lock()
                stderrData.append(data)
                dataLock.unlock()
                outputFileHandle?.write(data)
            }
        }

        // Registra processo per cancellazione
        processLock.lock()
        process = proc
        processLock.unlock()

        // Watchdog timeout
        var watchdog: DispatchWorkItem?
        if timeoutSeconds > 0 {
            let wd = DispatchWorkItem { [weak self] in
                self?.processLock.lock()
                let p = self?.process
                self?.processLock.unlock()
                if let p = p, p.isRunning {
                    p.terminate()
                    HelperLogger.forwardWarning(category: "Operations", message: "Timeout \(timeoutSeconds)s, processo terminato", tag: "[CommandExec]")
                }
            }
            watchdog = wd
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + .seconds(Int(timeoutSeconds)), execute: wd
            )
        }

        // Esegui
        do {
            try proc.run()
        } catch {
            watchdog?.cancel()
            outputFileHandle?.closeFile()
            return .failure(HelperError.operationFailed("Avvio processo fallito: \(error.localizedDescription)"))
        }

        // Attendi completamento
        proc.waitUntilExit()
        watchdog?.cancel()

        // Cleanup
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        stderrPipe.fileHandleForReading.readabilityHandler = nil

        // Leggi dati rimanenti
        let remainStdout = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let remainStderr = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        dataLock.lock()
        stdoutData.append(remainStdout)
        stderrData.append(remainStderr)
        dataLock.unlock()

        if !remainStdout.isEmpty { outputFileHandle?.write(remainStdout) }
        if !remainStderr.isEmpty { outputFileHandle?.write(remainStderr) }

        outputFileHandle?.closeFile()

        processLock.lock()
        process = nil
        processLock.unlock()

        let exitCode = proc.terminationStatus
        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""

        HelperLogger.operations.info("[CommandExec] Completato: exitCode=\(exitCode), stdout=\(stdoutData.count)B, stderr=\(stderrData.count)B")

        let result = CommandResult(stdout: stdout, stderr: stderr, exitCode: exitCode)
        do {
            let jsonData = try JSONEncoder().encode(result)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione risultato fallita: \(error)"))
        }
    }
}
