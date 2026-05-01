//
//  HelperDNSCache.swift
//  HelperDaemon
//
//  Cache DNS singleton per il helper privilegiato.
//  Risolve hostname in blocco con concorrenza controllata e TTL configurabile.
//  Evita query DNS ridondanti durante scan multipli.
//
//  v3.0: Fix race condition bulk resolve, purge periodica, logging errori DNS.
//

import Foundation
import os

/// Singleton DNS cache per il helper daemon.
/// Thread-safe tramite NSLock. TTL default 300s (5 minuti).
final class HelperDNSCache {

    static let shared = HelperDNSCache()

    /// Risultato singola risoluzione DNS
    struct DNSEntry: Codable {
        let ip: String
        let hostname: String?
        let resolvedAt: TimeInterval   // Date().timeIntervalSince1970
    }

    /// Risultato bulk resolve per serializzazione XPC
    struct BulkDNSResult: Codable {
        let entries: [DNSEntry]
        let resolvedCount: Int
        let failedCount: Int
        let durationMs: Double
    }

    // MARK: - Configurazione

    /// TTL cache in secondi (default 5 minuti)
    var ttlSeconds: TimeInterval = 300

    /// Intervallo purge automatica (default 10 minuti)
    private static let purgeIntervalSeconds: TimeInterval = 600

    // MARK: - Cache storage

    private struct CachedEntry {
        let hostname: String?
        let timestamp: Date
    }

    private var cache: [String: CachedEntry] = [:]
    private let lock = NSLock()

    /// Timer per purge periodica delle entry scadute
    private var purgeTimer: DispatchSourceTimer?

    private init() {
        startPurgeTimer()
    }

    deinit {
        purgeTimer?.cancel()
    }

    // MARK: - Purge periodica

    /// Avvia timer per pulizia automatica entry scadute
    private func startPurgeTimer() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + Self.purgeIntervalSeconds,
                       repeating: Self.purgeIntervalSeconds)
        timer.setEventHandler { [weak self] in
            self?.purgeExpired()
        }
        timer.resume()
        purgeTimer = timer
    }

    // MARK: - Lookup

    /// Cerca un hostname nella cache. Ritorna nil se non presente o scaduto.
    func lookup(_ ip: String) -> String? {
        lock.lock()
        defer { lock.unlock() }

        guard let entry = cache[ip] else { return nil }
        if Date().timeIntervalSince(entry.timestamp) > ttlSeconds {
            cache.removeValue(forKey: ip)
            return nil
        }
        return entry.hostname
    }

    /// Verifica se un IP è in cache (anche se hostname è nil = risoluzione fallita).
    /// Usato internamente per evitare ri-risoluzioni inutili.
    private func lookupEntry(_ ip: String) -> CachedEntry? {
        lock.lock()
        defer { lock.unlock() }

        guard let entry = cache[ip] else { return nil }
        if Date().timeIntervalSince(entry.timestamp) > ttlSeconds {
            cache.removeValue(forKey: ip)
            return nil
        }
        return entry
    }

    /// Inserisce un risultato nella cache.
    func store(_ ip: String, hostname: String?) {
        lock.lock()
        defer { lock.unlock() }
        cache[ip] = CachedEntry(hostname: hostname, timestamp: Date())
    }

    /// Svuota la cache.
    func flush() {
        lock.lock()
        defer { lock.unlock() }
        let count = cache.count
        cache.removeAll()
        HelperLogger.operations.info("[DNS] Cache svuotata: \(count) entry rimosse")
    }

    /// Rimuove le entry scadute.
    func purgeExpired() {
        lock.lock()
        let beforeCount = cache.count
        let now = Date()
        cache = cache.filter { now.timeIntervalSince($0.value.timestamp) <= ttlSeconds }
        let purged = beforeCount - cache.count
        lock.unlock()

        if purged > 0 {
            HelperLogger.operations.info("[DNS] Purge automatica: \(purged) entry scadute rimosse, \(beforeCount - purged) attive")
        }
    }

    /// Numero entry attualmente in cache (per diagnostica)
    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return cache.count
    }

    // MARK: - Bulk Resolve

    /// Risolve un array di IP in blocco con concorrenza controllata.
    /// Cache-first: se l'IP è già in cache (non scaduto), lo usa.
    /// Fix v3.0: sezione critica unica per check+store, evita race condition tra lookup e store.
    /// - Parameters:
    ///   - ips: Lista di IP da risolvere
    ///   - maxConcurrent: Concorrenza massima (default 20)
    ///   - timeoutPerHost: Timeout per singola risoluzione in secondi (default 2)
    /// - Returns: BulkDNSResult con tutti i risultati
    func bulkResolve(ips: [String], maxConcurrent: Int = 20,
                     timeoutPerHost: TimeInterval = 2.0) -> BulkDNSResult {

        let startTime = Date()
        var entries: [DNSEntry] = []
        let entriesLock = NSLock()
        var resolvedCount = 0
        var failedCount = 0
        var timeoutCount = 0

        let semaphore = DispatchSemaphore(value: maxConcurrent)
        let group = DispatchGroup()

        for ip in ips {
            // Sezione critica unica: controlla cache (hit + negative cache) in un solo lock.
            // Fix v3.0: prima c'erano due lock separati (lookup + check negative)
            // con finestra di race condition tra le due.
            if let cached = lookupEntry(ip) {
                entriesLock.lock()
                entries.append(DNSEntry(ip: ip, hostname: cached.hostname, resolvedAt: Date().timeIntervalSince1970))
                if cached.hostname != nil {
                    resolvedCount += 1
                } else {
                    failedCount += 1
                }
                entriesLock.unlock()
                continue
            }

            semaphore.wait()
            group.enter()

            DispatchQueue.global(qos: .utility).async { [weak self] in
                defer {
                    semaphore.signal()
                    group.leave()
                }

                guard let self else { return }
                let result = self.resolveWithTimeout(ip: ip, timeout: timeoutPerHost)
                self.store(ip, hostname: result.hostname)

                entriesLock.lock()
                entries.append(DNSEntry(ip: ip, hostname: result.hostname, resolvedAt: Date().timeIntervalSince1970))
                if result.hostname != nil {
                    resolvedCount += 1
                } else {
                    failedCount += 1
                    if result.timedOut { timeoutCount += 1 }
                }
                entriesLock.unlock()
            }
        }

        group.wait()

        let durationMs = Date().timeIntervalSince(startTime) * 1000.0

        if timeoutCount > 0 {
            HelperLogger.forwardWarning(
                category: "Operations",
                message: "Bulk DNS: \(timeoutCount) risoluzioni in timeout su \(ips.count) IP",
                tag: "[DNS]"
            )
        }

        HelperLogger.operations.info("[DNS] Bulk resolve: \(resolvedCount) risolti, \(failedCount) falliti (\(timeoutCount) timeout) su \(ips.count) IP in \(String(format: "%.0f", durationMs))ms")

        return BulkDNSResult(
            entries: entries.sorted { $0.ip < $1.ip },
            resolvedCount: resolvedCount,
            failedCount: failedCount,
            durationMs: durationMs
        )
    }

    // MARK: - Risoluzione singola

    /// Risultato risoluzione con dettaglio timeout
    private struct ResolveResult {
        let hostname: String?
        let timedOut: Bool
    }

    /// Risolve un singolo IP con timeout (reverse DNS).
    /// v3.0: ritorna ResolveResult con flag timeout per diagnostica.
    private func resolveWithTimeout(ip: String, timeout: TimeInterval) -> ResolveResult {
        var result: String?
        let semaphore = DispatchSemaphore(value: 0)

        DispatchQueue.global(qos: .utility).async {
            var hints = addrinfo()
            hints.ai_flags = AI_NUMERICHOST

            var addrResult: UnsafeMutablePointer<addrinfo>?
            let aiRet = getaddrinfo(ip, nil, &hints, &addrResult)
            defer { if addrResult != nil { freeaddrinfo(addrResult) } }

            guard aiRet == 0, let ai = addrResult else {
                HelperLogger.operations.debug("[DNS] getaddrinfo fallito per \(ip): codice \(aiRet)")
                semaphore.signal()
                return
            }

            var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let niRet = getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen,
                                     &hostBuf, socklen_t(NI_MAXHOST),
                                     nil, 0, NI_NAMEREQD)

            if niRet == 0 {
                let hostname = String(cString: hostBuf)
                // Ignora se il risultato è identico all'IP o è un pattern reverse DNS grezzo
                let lower = hostname.lowercased()
                if hostname != ip,
                   !lower.hasSuffix(".in-addr.arpa"),
                   !lower.hasSuffix(".ip6.arpa"),
                   !lower.hasSuffix(".in-addr.arpa."),
                   !lower.hasSuffix(".ip6.arpa.") {
                    result = hostname
                }
            }
            semaphore.signal()
        }

        let waitResult = semaphore.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            return ResolveResult(hostname: nil, timedOut: true)
        }
        return ResolveResult(hostname: result, timedOut: false)
    }
}
