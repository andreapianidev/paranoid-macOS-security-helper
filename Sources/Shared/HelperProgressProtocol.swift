//
//  HelperProgressProtocol.swift
//  IPscanner
//
//  Protocollo XPC per callback progressivi dall'helper verso l'app.
//  L'app esporta un oggetto che implementa questo protocollo come
//  exportedObject della connessione XPC, permettendo all'helper di
//  inviare risultati parziali in tempo reale.
//
//  Tutti i risultati serializzati come Data (JSON) per evitare NSSecureCoding complesso.
//

import Foundation

// MARK: - Modello Log Entry (Shared)

/// Entry di log dal helper, serializzata come JSON per XPC.
/// Solo warning/error vengono forwarded — info/debug restano solo su Console.app.
struct HelperLogEntry: Codable {
    let timestamp: Double      // Date().timeIntervalSince1970
    let level: String          // "warning" | "error"
    let category: String       // "General" | "Operations" | "Security"
    let message: String
    let operationTag: String?  // es. "[SYN]", "[MonitorMode]"
}

// MARK: - Protocollo Progress XPC

/// Protocollo XPC per callback progressivi (helper → app).
/// L'app registra un exportedObject con questa interfaccia per ricevere
/// risultati parziali durante operazioni lunghe.
@objc(HelperProgressProtocol)
protocol HelperProgressProtocol {

    /// Callback per ogni entry ARP trovata durante un ARP scan.
    /// - Parameter entryData: JSON Data con {ip: String, mac: String}
    func arpEntryFound(_ entryData: Data)

    /// Callback per ogni risultato porta trovato durante SYN/UDP scan.
    /// - Parameter resultData: JSON Data con {port: Int, state: String, latencyMs: Double?}
    func portResultFound(_ resultData: Data)

    /// Callback per ogni dispositivo trovato durante passive discovery.
    /// - Parameter deviceData: JSON Data con {ip: String, mac: String?, hostname: String?, source: String}
    func passiveDeviceFound(_ deviceData: Data)

    // MARK: - v2.0 Streaming generico

    /// Callback per aggiornamento progresso di un'operazione.
    /// - Parameters:
    ///   - operationId: ID univoco dell'operazione
    ///   - progressData: JSON Data con {percent: Double, message: String?, currentItem: String?}
    func operationProgress(_ operationId: String, progressData: Data)

    /// Callback per risultato parziale di un'operazione.
    /// Usato per SYN/UDP scan (singola porta), traceroute (singolo hop), ecc.
    /// - Parameters:
    ///   - operationId: ID univoco dell'operazione
    ///   - resultData: JSON Data con il risultato parziale (formato dipende dall'operazione)
    func operationPartialResult(_ operationId: String, resultData: Data)

    // MARK: - v2.7 Log Forwarding

    /// Callback per log warning/error dal helper verso la console diagnostica in-app.
    /// - Parameter logData: JSON Data di HelperLogEntry
    func helperLogReceived(_ logData: Data)
}
