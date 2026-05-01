//
//  HelperLogger.swift
//  HelperDaemon
//
//  Logging strutturato per l'helper privilegiato usando os.Logger.
//  Subsystem dedicato per filtrare in Console.app:
//    subsystem:com.paranoidipscanner.helper
//
//  v2.7: Forwarding warning/error via XPC alla console diagnostica in-app.
//  v3.0: Gestione errori XPC forwarding, contatore fallimenti, log startup.
//

import Foundation
import os

enum HelperLogger {
    /// Logging generale (startup, connessioni XPC)
    static let general = Logger(subsystem: "com.paranoidipscanner.helper", category: "General")

    /// Logging operazioni (scan, discovery, detection)
    static let operations = Logger(subsystem: "com.paranoidipscanner.helper", category: "Operations")

    /// Logging sicurezza (code-signing, validazione input)
    static let security = Logger(subsystem: "com.paranoidipscanner.helper", category: "Security")

    // MARK: - XPC Log Forwarding (v2.7)

    /// Connessione XPC corrente per forwarding log. Impostata da HelperDaemonDelegate.
    /// weak: non trattiene la connessione
    static weak var xpcConnection: NSXPCConnection?

    /// Contatore fallimenti XPC consecutivi (reset a ogni successo/riconnessione).
    /// Dopo 5 fallimenti consecutivi disabilita forwarding per evitare spam in syslog.
    private static var xpcFailureCount = 0
    private static let xpcFailureThreshold = 5
    private static let xpcCountLock = NSLock()

    /// Reset contatore fallimenti (chiamato quando la connessione si rinnova)
    static func resetXPCFailureCount() {
        xpcCountLock.lock()
        xpcFailureCount = 0
        xpcCountLock.unlock()
    }

    /// Forward un warning sia su os.Logger che via XPC alla console diagnostica in-app.
    static func forwardWarning(category: String, message: String, tag: String? = nil) {
        let logger = loggerForCategory(category)
        if let tag {
            logger.warning("\(tag, privacy: .public) \(message, privacy: .public)")
        } else {
            logger.warning("\(message, privacy: .public)")
        }
        sendToApp(level: "warning", category: category, message: message, tag: tag)
    }

    /// Forward un errore sia su os.Logger che via XPC alla console diagnostica in-app.
    static func forwardError(category: String, message: String, tag: String? = nil) {
        let logger = loggerForCategory(category)
        if let tag {
            logger.error("\(tag, privacy: .public) \(message, privacy: .public)")
        } else {
            logger.error("\(message, privacy: .public)")
        }
        sendToApp(level: "error", category: category, message: message, tag: tag)
    }

    /// Forward info-level log via XPC alla app (usato per live stats monitor mode, ecc.)
    static func forwardInfo(category: String, message: String, tag: String? = nil) {
        let logger = loggerForCategory(category)
        if let tag {
            logger.info("\(tag, privacy: .public) \(message, privacy: .public)")
        } else {
            logger.info("\(message, privacy: .public)")
        }
        sendToApp(level: "info", category: category, message: message, tag: tag)
    }

    // MARK: - Interni

    private static func loggerForCategory(_ category: String) -> Logger {
        switch category {
        case "General": return general
        case "Security": return security
        default: return operations
        }
    }

    /// Coda dedicata per invio XPC — evita buffering quando il thread chiamante
    /// è bloccato (es. pcap capture loop in MonitorModeOperation)
    private static let xpcSendQueue = DispatchQueue(label: "com.paranoidipscanner.helper.logXPC")

    /// Serializza HelperLogEntry e invia via XPC.
    /// v3.0: gestisce errori proxy, conta fallimenti consecutivi, disabilita se app disconnessa.
    private static func sendToApp(level: String, category: String, message: String, tag: String?) {
        guard let connection = xpcConnection else { return }

        // Se troppi fallimenti consecutivi, skip — evita spam inutile
        xpcCountLock.lock()
        let shouldSkip = xpcFailureCount >= xpcFailureThreshold
        xpcCountLock.unlock()
        if shouldSkip { return }

        let entry = HelperLogEntry(
            timestamp: Date().timeIntervalSince1970,
            level: level,
            category: category,
            message: message,
            operationTag: tag
        )

        guard let data = try? JSONEncoder().encode(entry) else { return }

        xpcSendQueue.async {
            // Usa remoteObjectProxyWithErrorHandler per rilevare disconnessione
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                xpcCountLock.lock()
                xpcFailureCount += 1
                let count = xpcFailureCount
                xpcCountLock.unlock()
                if count == xpcFailureThreshold {
                    general.warning("XPC log forwarding disabilitato dopo \(count) fallimenti: \(error.localizedDescription, privacy: .public)")
                }
            } as? HelperProgressProtocol

            proxy?.helperLogReceived(data)
        }
    }
}
