//
//  main.swift
//  HelperDaemon
//
//  Entry point dell'helper privilegiato (LaunchDaemon root).
//  Registra un NSXPCListener sul Mach service name e avvia il RunLoop.
//

import Foundation
import os

HelperLogger.general.info("Helper daemon v\(HelperConstants.helperVersion, privacy: .public) avviato — pid \(ProcessInfo.processInfo.processIdentifier)")

let delegate = HelperDaemonDelegate()
let listener = NSXPCListener(machServiceName: HelperConstants.machServiceName)
listener.delegate = delegate
listener.resume()

HelperLogger.general.info("XPC listener attivo su \(HelperConstants.machServiceName, privacy: .public)")

RunLoop.current.run()
