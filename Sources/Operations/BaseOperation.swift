//
//  BaseOperation.swift
//  HelperDaemon
//
//  Classe base per tutte le operazioni privilegiate.
//  Fornisce accesso atomico thread-safe al flag isCancelled
//  tramite NSLock, eliminando data race su Bool da thread concorrenti.
//

import Foundation

class BaseOperation: CancellableOperation {

    private let _cancelLock = NSLock()
    private var _cancelled = false

    /// Flag di cancellazione thread-safe (lettura atomica)
    var isCancelled: Bool {
        _cancelLock.lock()
        defer { _cancelLock.unlock() }
        return _cancelled
    }

    /// Cancella l'operazione. Sottoclassi devono chiamare super.cancel()
    /// e poi eseguire cleanup specifico (pcap_breakloop, process.terminate, ecc.)
    func cancel() {
        _cancelLock.lock()
        _cancelled = true
        _cancelLock.unlock()
    }
}
