//
//  HelperDaemonDelegate.swift
//  HelperDaemon
//
//  Delegate del listener XPC. Verifica il code-signing del chiamante
//  prima di accettare la connessione, e configura i protocolli XPC.
//

import Foundation
import os
import Security

class HelperDaemonDelegate: NSObject, NSXPCListenerDelegate {

    private let operations = HelperDaemonOperations()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        // Verifica code-signing del chiamante
        guard verifyCallerCodeSigning(connection: newConnection) else {
            HelperLogger.forwardWarning(category: "Security", message: "Connessione rifiutata: code-signing non valido")
            return false
        }

        // Configura interfaccia XPC esportata (helper → app)
        newConnection.exportedInterface = NSXPCInterface(with: PrivilegedHelperProtocol.self)
        newConnection.exportedObject = operations

        // Configura interfaccia remota (app → helper, callback progressivi)
        newConnection.remoteObjectInterface = NSXPCInterface(with: HelperProgressProtocol.self)

        // Handler invalidazione
        newConnection.invalidationHandler = {
            HelperLogger.general.info("Connessione XPC invalidata")
            HelperLogger.xpcConnection = nil
        }
        newConnection.interruptionHandler = {
            HelperLogger.general.warning("Connessione XPC interrotta")
            HelperLogger.xpcConnection = nil
        }

        newConnection.resume()

        // Rende la connessione disponibile per il forwarding log (v2.7)
        HelperLogger.xpcConnection = newConnection
        HelperLogger.resetXPCFailureCount()
        HelperLogger.general.info("Connessione XPC accettata (pid: \(newConnection.processIdentifier))")
        return true
    }

    // MARK: - Verifica Code-Signing

    /// Verifica che il processo chiamante soddisfi il requisito di firma dell'app
    private func verifyCallerCodeSigning(connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier

        var code: SecCode?
        var attributes = [String: Any]()
        attributes[kSecGuestAttributePid as String] = pid

        let status = SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code)
        guard status == errSecSuccess, let secCode = code else {
            HelperLogger.forwardError(category: "Security", message: "SecCodeCopyGuestWithAttributes fallito: \(status)")
            return false
        }

        // Verifica con il requisito di firma dell'app principale
        var requirement: SecRequirement?
        let reqString = HelperConstants.appSigningRequirement
        let reqStatus = SecRequirementCreateWithString(reqString as CFString, [], &requirement)
        guard reqStatus == errSecSuccess, let secRequirement = requirement else {
            HelperLogger.forwardError(category: "Security", message: "SecRequirementCreateWithString fallito: \(reqStatus)")
            return false
        }

        let validStatus = SecCodeCheckValidity(secCode, [], secRequirement)
        if validStatus != errSecSuccess {
            HelperLogger.forwardWarning(category: "Security", message: "Verifica code-signing fallita per pid \(pid): \(validStatus)")
            return false
        }

        return true
    }
}
