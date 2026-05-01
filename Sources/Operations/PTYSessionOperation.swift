//
//  PTYSessionOperation.swift
//  HelperDaemon
//
//  Sessione PTY persistente come root via forkpty().
//  Lo stdout+stderr (fusi sul master fd) viene appeso a un file di output
//  per streaming real-time dall'app via polling.
//  L'input viene scritto sul master fd dall'app via writePTYInput.
//
//  La sessione resta viva finché:
//  - l'app chiama closePTYSession,
//  - la shell esce (master fd EOF),
//  - cancel() viene invocato (SIGHUP al pgid + close fd).
//

import Foundation
import Darwin
import os

/// Funzione C `forkpty` da `<util.h>` non esposta automaticamente nei
/// module map Swift; la dichiariamo manualmente come @_silgen_name.
@_silgen_name("forkpty")
private func c_forkpty(_ amaster: UnsafeMutablePointer<Int32>,
                       _ name: UnsafeMutablePointer<CChar>?,
                       _ termp: OpaquePointer?,
                       _ winp: UnsafeMutablePointer<winsize>?) -> pid_t

class PTYSessionOperation: BaseOperation {

    // MARK: - Whitelist shell

    /// Solo shell di sistema, niente eseguibili custom.
    private static let allowedShells: Set<String> = [
        "/bin/zsh",
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/zsh",
        "/usr/bin/bash",
        "/usr/bin/sh"
    ]

    // MARK: - Env sanitization

    /// Variabili d'ambiente bloccate quando passate dall'app. Eseguendo come root,
    /// DYLD_*/LD_* possono iniettare librerie arbitrarie nel processo figlio.
    /// MallocNanoZone/MallocStackLogging permettono allocator hijack/diagnostica
    /// non desiderata. Le filtriamo prima del merge per zero-trust verso l'app.
    private static let dangerousEnvKeys: Set<String> = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_PRINT_LIBRARIES",
        "DYLD_PRINT_BINDINGS",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "DYLD_VERSIONED_LIBRARY_PATH",
        "DYLD_VERSIONED_FRAMEWORK_PATH",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_AUDIT",
        "MallocNanoZone",
        "MallocStackLogging",
        "MallocStackLoggingNoCompact",
        "MALLOC_PROTECT_BEFORE",
        "NSUnbufferedIO"
    ]

    /// Prefissi di chiavi env vietati (es. tutto ciò che inizia con DYLD_ o LD_)
    /// per coprire varianti future.
    private static let dangerousEnvPrefixes: [String] = [
        "DYLD_",
        "LD_"
    ]

    private static func isDangerousEnvKey(_ key: String) -> Bool {
        if dangerousEnvKeys.contains(key) { return true }
        let upper = key.uppercased()
        return dangerousEnvPrefixes.contains { upper.hasPrefix($0) }
    }

    /// Canonicalizza un path via `realpath(3)` POSIX (resolve simlink + ".."/"." +
    /// path relativi accedendo al filesystem). Ritorna nil se il file non esiste
    /// o se realpath fallisce. Più strict di `resolvingSymlinksInPath` (Foundation).
    private static func canonicalPath(_ path: String) -> String? {
        return path.withCString { cstr in
            // PATH_MAX = 1024 su Darwin
            var buffer = [CChar](repeating: 0, count: 1024)
            guard realpath(cstr, &buffer) != nil else { return nil }
            return String(cString: buffer)
        }
    }

    // MARK: - Stato sessione

    private let stateLock = NSLock()
    private var masterFD: Int32 = -1
    private var childPID: pid_t = -1
    private var outputFileHandle: FileHandle?
    private var readSource: DispatchSourceRead?
    /// Flag completamento per sbloccare execute()
    private let doneSemaphore = DispatchSemaphore(value: 0)
    /// Idle watchdog: se nessuna scrittura per N secondi, chiudi la sessione.
    /// 0 = disabilitato. Default 30 minuti.
    private static let idleTimeoutSeconds: TimeInterval = 30 * 60
    private var lastActivity: Date = Date()
    private var idleTimer: DispatchSourceTimer?

    // MARK: - API

    struct OpenResult: Codable {
        let pid: Int32
        let opened: Bool
    }

    struct WriteResult: Codable {
        let written: Int
    }

    /// Apre la sessione PTY. Ritorna immediatamente dopo il fork con il PID,
    /// poi resta in background fino a EOF/close per drenare il master fd.
    func execute(shellPath: String, arguments: [String], environment: [String: String],
                 cols: Int32, rows: Int32, outputFile: String) -> Result<Data, Error> {

        // Validazione path shell. Usiamo realpath(3) POSIX invece di
        // NSString.resolvingSymlinksInPath: realpath canonizza tutti i symlink
        // e i ".."/"." accedendo al filesystem, garantendo path assoluto reale.
        // resolvingSymlinksInPath lavora a livello stringa e può mancare alcuni
        // edge case (path relativi, simlink farm), aprendo a bypass whitelist.
        guard let resolved = Self.canonicalPath(shellPath) else {
            return .failure(HelperError.invalidParameters(
                "Shell path non risolvibile: \(shellPath)"
            ))
        }
        guard Self.allowedShells.contains(resolved) else {
            return .failure(HelperError.invalidParameters(
                "Shell non consentita: \(shellPath) (canonico: \(resolved)). Permesse: \(Self.allowedShells.sorted().joined(separator: ", "))"
            ))
        }
        guard FileManager.default.isExecutableFile(atPath: resolved) else {
            return .failure(HelperError.invalidParameters("Shell non eseguibile: \(resolved)"))
        }

        // Apri output file in append. Tronca eventuale residuo da run precedenti
        // sullo stesso path, così l'app legge da offset 0 senza vedere dati vecchi.
        FileManager.default.createFile(atPath: outputFile, contents: nil)
        guard let outHandle = FileHandle(forWritingAtPath: outputFile) else {
            return .failure(HelperError.operationFailed("Impossibile aprire outputFile: \(outputFile)"))
        }
        // Closure che chiude l'handle se torniamo da execute() prima di
        // affidarlo a outputFileHandle. Ad assignment ownership trasferita.
        var ownsOutHandle = true
        defer {
            if ownsOutHandle { outHandle.closeFile() }
        }

        // Costruisci winsize iniziale
        var winsz = winsize(ws_row: UInt16(max(rows, 1)),
                            ws_col: UInt16(max(cols, 1)),
                            ws_xpixel: 0, ws_ypixel: 0)

        var amaster: Int32 = -1
        let pid = withUnsafeMutablePointer(to: &winsz) { wptr in
            c_forkpty(&amaster, nil, nil, wptr)
        }

        if pid < 0 {
            // ownsOutHandle resta true → defer chiude l'handle.
            let err = String(cString: strerror(errno))
            return .failure(HelperError.operationFailed("forkpty fallito: \(err)"))
        }

        if pid == 0 {
            // Child: setup environment + exec shell. Stdin/stdout/stderr già
            // collegati al lato slave dal forkpty; non abbiamo accesso al master qui.

            // Costruisci env: parti da quello del daemon (già filtrato dal kernel
            // per i daemon launchctl) e applica solo i sovrascritti app dopo aver
            // filtrato chiavi pericolose. Eseguendo come root dobbiamo essere
            // zero-trust verso l'app: DYLD_*/LD_* permettono code injection.
            var envDict = ProcessInfo.processInfo.environment
            // Strip eventuali residui anche dall'env del daemon stesso.
            // Iteriamo un Array snapshot per evitare mutazione durante iterazione.
            for key in Array(envDict.keys) where Self.isDangerousEnvKey(key) {
                envDict.removeValue(forKey: key)
            }
            envDict["TERM"] = envDict["TERM"] ?? "xterm-256color"
            envDict["LC_ALL"] = envDict["LC_ALL"] ?? "en_US.UTF-8"
            envDict["LANG"] = envDict["LANG"] ?? "en_US.UTF-8"
            envDict["PATH"] = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
            for (k, v) in environment {
                if Self.isDangerousEnvKey(k) { continue }
                envDict[k] = v
            }

            // execve richiede argv e envp come array C-string null-terminated.
            var argv: [UnsafeMutablePointer<CChar>?] = []
            argv.append(strdup(resolved))
            for arg in arguments {
                argv.append(strdup(arg))
            }
            argv.append(nil)

            var envp: [UnsafeMutablePointer<CChar>?] = []
            for (k, v) in envDict {
                envp.append(strdup("\(k)=\(v)"))
            }
            envp.append(nil)

            // Cambia cwd a /tmp se quella corrente non è leggibile (LaunchDaemon
            // tipicamente parte da /, va bene).
            execve(resolved, argv, envp)
            // Se torniamo da execve è errore.
            _exit(127)
        }

        // Parent: registra stato, avvia drain del master fd in background.
        // Ownership di outHandle passa a outputFileHandle: il defer non chiude più.
        stateLock.lock()
        masterFD = amaster
        childPID = pid
        outputFileHandle = outHandle
        lastActivity = Date()
        stateLock.unlock()
        ownsOutHandle = false

        startReadDrain()
        startIdleWatchdog()

        HelperLogger.operations.info("[PTY] Sessione aperta: pid=\(pid, privacy: .public) shell=\(resolved, privacy: .public)")

        // Notifica il chiamante con OpenResult prima di attendere.
        // Trucchetto: il dispatcher chiama execute() in background, quindi
        // possiamo bloccare qui finché la sessione non si chiude, e poi
        // ritornare. Il chiamante riceverà il reply solo a chiusura — ma
        // l'app ha bisogno del PID subito. Quindi NON blocchiamo: ritorniamo
        // OpenResult immediatamente e drain/watchdog girano fino a chiusura.
        let result = OpenResult(pid: pid, opened: true)
        do {
            let data = try JSONEncoder().encode(result)
            return .success(data)
        } catch {
            // Sessione già attiva ma reply non spedibile: chiudo per evitare leak.
            closeSession()
            return .failure(HelperError.operationFailed("Encoding OpenResult fallito: \(error)"))
        }
    }

    // MARK: - Write

    /// Scrive bytes sul master fd. Ritorna numero di byte scritti.
    func writeInput(_ data: Data) -> Result<Data, Error> {
        stateLock.lock()
        let fd = masterFD
        stateLock.unlock()

        guard fd >= 0 else {
            return .failure(HelperError.operationFailed("Sessione PTY non aperta"))
        }

        let written = data.withUnsafeBytes { buf -> Int in
            guard let base = buf.baseAddress else { return 0 }
            return write(fd, base, buf.count)
        }

        if written < 0 {
            let err = String(cString: strerror(errno))
            return .failure(HelperError.operationFailed("write() su PTY fallita: \(err)"))
        }

        stateLock.lock()
        lastActivity = Date()
        stateLock.unlock()

        let result = WriteResult(written: written)
        do {
            return .success(try JSONEncoder().encode(result))
        } catch {
            return .failure(HelperError.operationFailed("Encoding WriteResult: \(error)"))
        }
    }

    // MARK: - Resize

    func resize(cols: Int32, rows: Int32) -> Bool {
        stateLock.lock()
        let fd = masterFD
        stateLock.unlock()

        guard fd >= 0 else { return false }

        let rc = pty_set_winsize(fd, UInt16(max(rows, 1)), UInt16(max(cols, 1)))
        return rc == 0
    }

    // MARK: - Cancel / Close

    override func cancel() {
        super.cancel()
        closeSession()
    }

    /// Chiude la sessione: invia SIGHUP al pgid del child e chiude master fd.
    func closeSession() {
        stateLock.lock()
        let fd = masterFD
        let pid = childPID
        let source = readSource
        let timer = idleTimer
        let outHandle = outputFileHandle
        masterFD = -1
        childPID = -1
        readSource = nil
        idleTimer = nil
        outputFileHandle = nil
        stateLock.unlock()

        timer?.cancel()
        source?.cancel()

        if pid > 0 {
            // SIGHUP al gruppo di processi della shell
            killpg(pid, SIGHUP)
            // Reap non bloccante (no zombie)
            var status: Int32 = 0
            _ = waitpid(pid, &status, WNOHANG)
        }
        if fd >= 0 {
            close(fd)
        }
        outHandle?.closeFile()

        // Sblocca eventuale waiter (qui non usato, ma manteniamo simmetria)
        doneSemaphore.signal()

        HelperLogger.operations.info("[PTY] Sessione chiusa: pid=\(pid, privacy: .public)")
    }

    // MARK: - Drain master fd → outputFile

    private func startReadDrain() {
        stateLock.lock()
        let fd = masterFD
        stateLock.unlock()

        guard fd >= 0 else { return }

        let queue = DispatchQueue(label: "pty.drain.\(fd)", qos: .userInitiated)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)

        source.setEventHandler { [weak self] in
            guard let self = self else { return }
            var buf = [UInt8](repeating: 0, count: 8192)
            let n = buf.withUnsafeMutableBufferPointer { ptr -> Int in
                return read(fd, ptr.baseAddress, ptr.count)
            }
            if n > 0 {
                let data = Data(buf.prefix(n))
                self.stateLock.lock()
                let h = self.outputFileHandle
                self.lastActivity = Date()
                self.stateLock.unlock()
                h?.write(data)
            } else if n == 0 {
                // EOF: child è uscito
                HelperLogger.operations.info("[PTY] EOF su master fd, chiudo sessione")
                self.closeSession()
            } else {
                // n < 0: errore. EAGAIN su read di fd non-blocking è benigno.
                if errno != EAGAIN && errno != EINTR {
                    let err = String(cString: strerror(errno))
                    HelperLogger.forwardWarning(category: "Operations",
                                                message: "read() su master PTY fallita: \(err)",
                                                tag: "[PTY]")
                    self.closeSession()
                }
            }
        }

        source.setCancelHandler { /* nothing extra */ }
        source.resume()

        stateLock.lock()
        readSource = source
        stateLock.unlock()
    }

    // MARK: - Idle watchdog

    private func startIdleWatchdog() {
        guard Self.idleTimeoutSeconds > 0 else { return }
        let queue = DispatchQueue(label: "pty.idle", qos: .utility)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.stateLock.lock()
            let last = self.lastActivity
            self.stateLock.unlock()
            if Date().timeIntervalSince(last) > Self.idleTimeoutSeconds {
                HelperLogger.forwardWarning(category: "Operations",
                                            message: "Idle timeout (\(Int(Self.idleTimeoutSeconds))s) raggiunto, chiudo sessione",
                                            tag: "[PTY]")
                self.closeSession()
            }
        }
        timer.resume()
        stateLock.lock()
        idleTimer = timer
        stateLock.unlock()
    }
}
