//
//  HelperConstants.swift
//  IPscanner
//
//  Costanti condivise tra app principale e helper privilegiato.
//  Incluso in entrambi i target.
//

import Foundation

enum HelperConstants {
    /// Bundle ID dell'helper privilegiato (usato come Mach service name)
    static let helperBundleID = "andreapiani.IPscanner.helper"

    /// Nome del Mach service per la connessione XPC
    static let machServiceName = "andreapiani.IPscanner.helper"

    /// Bundle ID dell'app principale
    static let appBundleID = "andreapiani.IPscanner"

    /// Team ID sviluppatore
    static let teamID = "ERAK83QBBM"

    /// Versione corrente dell'helper
    static let helperVersion = "3.10.0"

    /// Requisito code-signing per verificare l'app dal lato helper
    static let appSigningRequirement = """
        anchor apple generic and identifier "\(appBundleID)" \
        and certificate leaf[subject.OU] = "\(teamID)"
        """

    /// Requisito code-signing per verificare l'helper dal lato app
    static let helperSigningRequirement = """
        anchor apple generic and identifier "\(helperBundleID)" \
        and certificate leaf[subject.OU] = "\(teamID)"
        """
}
