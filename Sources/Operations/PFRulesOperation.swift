//
//  PFRulesOperation.swift
//  HelperDaemon
//
//  Gestione regole pf (packet filter) per honeypot:
//  - Anchor "com.apple/250.ParanoidBlocks" per blocchi IP attaccanti
//  - Anchor "com.apple/250.ParanoidRedirect" per port redirect (22→8022 ecc.)
//
//  Le anchor sotto "com.apple/" vengono caricate automaticamente da /etc/pf.conf
//  default macOS (anchor "com.apple/*" + rdr-anchor "com.apple/*" presenti).
//  Questo evita di modificare /etc/pf.conf.
//

import Foundation
import os

class PFRulesOperation: BaseOperation {

    static let blockAnchor = "com.apple/250.ParanoidBlocks"
    static let redirectAnchor = "com.apple/250.ParanoidRedirect"

    // MARK: - Modelli

    struct ApplyBlocksResult: Codable {
        let applied: Int
        let anchor: String
        let pfEnabled: Bool
    }

    struct RedirectRule: Codable {
        let from: Int       // porta esterna (es. 22)
        let to: Int         // porta locale honeypot (es. 8022)
        let iface: String   // interfaccia (es. "en0"); vuota = qualsiasi
        let proto: String?  // "tcp" (default) o "udp"
    }

    struct ApplyRedirectsResult: Codable {
        let applied: Int
        let anchor: String
        let pfEnabled: Bool
    }

    struct ClearResult: Codable {
        let cleared: [String]
    }

    // MARK: - API pubblica

    /// Applica blocchi su array di IP (anchor paranoid_block).
    /// Sostituisce completamente le regole nell'anchor.
    static func applyBlocks(ips: [String]) throws -> ApplyBlocksResult {
        // Filtra IP validi (IPv4 + IPv6)
        let validIPs = ips.filter { isValidIP($0) }

        // Garantisce che pf sia abilitato — ignora errore "already enabled"
        let pfEnabled = ensurePFEnabled()

        if validIPs.isEmpty {
            // Svuota anchor
            _ = runPFCTL(args: ["-a", blockAnchor, "-F", "rules"])
            return ApplyBlocksResult(applied: 0, anchor: blockAnchor, pfEnabled: pfEnabled)
        }

        // Costruisce ruleset: block in/out quick per ogni IP
        var rules = "# Paranoid IPscanner — Block anchor (auto-generated)\n"
        for ip in validIPs {
            // "from" blocca pacchetti in ingresso, "to" blocca traffico in uscita verso quell'IP
            rules += "block drop in quick from \(ip) to any\n"
            rules += "block drop out quick to \(ip)\n"
        }

        // Scrive file temporaneo + carica nell'anchor
        try writeAndLoadAnchor(anchor: blockAnchor, rules: rules)

        return ApplyBlocksResult(applied: validIPs.count, anchor: blockAnchor, pfEnabled: pfEnabled)
    }

    /// Applica regole rdr (anchor paranoid_redirect).
    /// Le porte privilegiate vengono dirottate alle porte locali del honeypot.
    static func applyRedirects(redirects: [RedirectRule]) throws -> ApplyRedirectsResult {
        let valid = redirects.filter { isValidRedirect($0) }
        let pfEnabled = ensurePFEnabled()

        if valid.isEmpty {
            _ = runPFCTL(args: ["-a", redirectAnchor, "-F", "rules"])
            return ApplyRedirectsResult(applied: 0, anchor: redirectAnchor, pfEnabled: pfEnabled)
        }

        var rules = "# Paranoid IPscanner — Redirect anchor (auto-generated)\n"
        for r in valid {
            let proto = (r.proto?.lowercased() == "udp") ? "udp" : "tcp"
            let ifacePart = r.iface.isEmpty ? "" : "on \(r.iface) "
            // rdr deve precedere le filter rules nella sintassi pf legacy.
            // Anchor separato: pfctl gestisce ordering autonomamente (rdr-anchor + anchor).
            rules += "rdr \(ifacePart)inet proto \(proto) from any to any port \(r.from) -> 127.0.0.1 port \(r.to)\n"
        }

        try writeAndLoadAnchor(anchor: redirectAnchor, rules: rules)

        return ApplyRedirectsResult(applied: valid.count, anchor: redirectAnchor, pfEnabled: pfEnabled)
    }

    /// Svuota anchor blocks e/o redirects. Non disabilita pf globale.
    static func clear(blocks: Bool, redirects: Bool) -> ClearResult {
        var cleared: [String] = []
        if blocks {
            _ = runPFCTL(args: ["-a", blockAnchor, "-F", "rules"])
            cleared.append(blockAnchor)
        }
        if redirects {
            _ = runPFCTL(args: ["-a", redirectAnchor, "-F", "rules"])
            cleared.append(redirectAnchor)
        }
        return ClearResult(cleared: cleared)
    }

    // MARK: - Helpers

    /// Validazione IP: accetta IPv4 dotted-quad o IPv6.
    /// Usa inet_pton per evitare regex fragili.
    private static func isValidIP(_ ip: String) -> Bool {
        var sin = sockaddr_in()
        if inet_pton(AF_INET, ip, &sin.sin_addr) == 1 { return true }
        var sin6 = sockaddr_in6()
        if inet_pton(AF_INET6, ip, &sin6.sin6_addr) == 1 { return true }
        return false
    }

    /// Validazione regola redirect: porte 1-65535, iface alfanumerica, proto opzionale.
    private static func isValidRedirect(_ r: RedirectRule) -> Bool {
        guard r.from > 0 && r.from < 65536 else { return false }
        guard r.to > 0 && r.to < 65536 else { return false }
        // iface può essere vuota oppure deve essere alfanumerica + cifre (en0, lo0, utun3)
        if !r.iface.isEmpty {
            let allowed = CharacterSet.alphanumerics
            guard r.iface.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return false }
        }
        if let p = r.proto?.lowercased(), p != "tcp" && p != "udp" { return false }
        return true
    }

    /// Abilita pf con `pfctl -e`. Se già abilitato, pfctl stampa "pf already enabled"
    /// su stderr e termina con exit code 0. Non usiamo `-E` (ref-counted) per evitare
    /// di accumulare token che restano vivi anche dopo l'uscita dell'app.
    /// Ritorna true se pf risulta abilitato dopo la chiamata.
    @discardableResult
    private static func ensurePFEnabled() -> Bool {
        let result = runPFCTL(args: ["-e"])
        if result.exitCode == 0 { return true }
        // Fallback: interroga lo stato direttamente
        let status = runPFCTL(args: ["-s", "info"])
        return status.stdout.contains("Status: Enabled")
    }

    /// Esegue pfctl con args e cattura output.
    private static func runPFCTL(args: [String]) -> (stdout: String, stderr: String, exitCode: Int32) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        process.arguments = args

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return ("", "Failed to launch pfctl: \(error)", -1)
        }

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""

        return (stdout, stderr, process.terminationStatus)
    }

    /// Scrive le regole su file temporaneo e le carica nell'anchor specificato.
    private static func writeAndLoadAnchor(anchor: String, rules: String) throws {
        let tmpDir = NSTemporaryDirectory()
        let fileName = "paranoid_pf_\(UUID().uuidString).conf"
        let tmpPath = (tmpDir as NSString).appendingPathComponent(fileName)

        try rules.write(toFile: tmpPath, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        let result = runPFCTL(args: ["-a", anchor, "-f", tmpPath])
        if result.exitCode != 0 {
            HelperLogger.operations.error("[PF] pfctl failed exit=\(result.exitCode, privacy: .public) stderr=\(result.stderr, privacy: .public)")
            throw NSError(
                domain: "PFRulesOperation",
                code: Int(result.exitCode),
                userInfo: [NSLocalizedDescriptionKey: "pfctl error: \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"]
            )
        }
        HelperLogger.operations.info("[PF] anchor=\(anchor, privacy: .public) loaded successfully")
    }
}
