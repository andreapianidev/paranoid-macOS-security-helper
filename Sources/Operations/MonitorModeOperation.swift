//
//  MonitorModeOperation.swift
//  HelperDaemon
//
//  Operazione di cattura frame 802.11 raw in monitor mode via pcap_set_rfmon.
//  Parsa RadioTap header + IEEE 802.11 frame header per estrarre beacon, probe
//  request/response, deauth, EAPOL e data frame. Supporta channel hopping.
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//

import Foundation
import os

// MARK: - 802.11 Frame Constants

private let IEEE80211_TYPE_MANAGEMENT: UInt8 = 0x00
private let IEEE80211_TYPE_CONTROL: UInt8    = 0x04
private let IEEE80211_TYPE_DATA: UInt8       = 0x08

private let IEEE80211_SUBTYPE_ASSOC_REQ: UInt8     = 0x00
private let IEEE80211_SUBTYPE_ASSOC_RESP: UInt8    = 0x10
private let IEEE80211_SUBTYPE_PROBE_REQ: UInt8     = 0x40
private let IEEE80211_SUBTYPE_PROBE_RESP: UInt8    = 0x50
private let IEEE80211_SUBTYPE_BEACON: UInt8        = 0x80
private let IEEE80211_SUBTYPE_DISASSOC: UInt8      = 0xA0
private let IEEE80211_SUBTYPE_AUTH: UInt8           = 0xB0
private let IEEE80211_SUBTYPE_DEAUTH: UInt8        = 0xC0

private let EAPOL_ETHERTYPE: UInt16 = 0x888E

// MARK: - Result Structures (Codable for JSON serialization via XPC)

struct MonitorBeaconEntry: Codable {
    let bssid: String
    let ssid: String
    let channel: Int
    let rssi: Int
    let crypto: String         // "WPA2", "WPA3", "WEP", "Open"
    let isHidden: Bool
    let timestamp: Double      // timeIntervalSince1970
    let htCapabilities: Bool
    let vhtCapabilities: Bool
    let wpsEnabled: Bool       // WPS presente (IE 221, OUI 00:50:F2 type 4)
    let pmfCapable: Bool       // Protected Management Frames (RSN Cap bit 7)
    let pmfRequired: Bool      // PMF obbligatorio (RSN Cap bit 6)
    let groupCipher: String    // "CCMP", "TKIP", "WEP40", "WEP104", "Unknown"
}

struct MonitorProbeRequestEntry: Codable {
    let sourceMac: String
    let ssidsSearched: [String]
    let rssi: Int
    let isRandomizedMAC: Bool
    let timestamp: Double
    let ieSignature: [UInt8]   // Lista ordinata IE ID per OS fingerprinting passivo
}

struct MonitorDeauthEntry: Codable {
    let sourceMac: String
    let destMac: String
    let bssid: String
    let reasonCode: Int
    let reasonDescription: String
    let timestamp: Double
}

struct MonitorEAPOLEntry: Codable {
    let sourceMac: String
    let destMac: String
    let bssid: String
    let messageNumber: Int     // 1-4 del 4-way handshake
    let rawHex: String         // EAPOL frame hex per export
    let timestamp: Double
}

struct MonitorClientAssociation: Codable {
    let clientMac: String
    let apBssid: String
    let rssi: Int
    let timestamp: Double
}

struct MonitorChannelStats: Codable {
    let channel: Int
    let totalFrames: Int
    let dataFrames: Int
    let mgmtFrames: Int
    let ctrlFrames: Int
}

struct MonitorHiddenSSID: Codable {
    let bssid: String
    let revealedSSID: String
    let method: String         // "probe_response" or "association"
}

// MARK: - Threat Detection Structures

struct MonitorThreatAlertEntry: Codable {
    let type: String       // "evil_twin", "karma_mana", "beacon_flood", etc.
    let severity: String   // "info", "warning", "critical"
    let title: String
    let description: String
    let involvedMACs: [String]
    let timestamp: Double
}

struct MonitorSignalIntelEntry: Codable {
    let mac: String
    let rssiSamples: [MonitorRSSISampleEntry]
    let trend: String       // "approaching", "departing", "stable"
    let averageRSSI: Int
    let latestRSSI: Int
    let firstSeen: Double
    let lastSeen: Double
}

struct MonitorRSSISampleEntry: Codable {
    let timestamp: Double
    let rssi: Int
}

struct MonitorCaptureDiagnostics: Codable {
    let activateStatus: Int          // pcap_activate return (0=OK, >0=warning)
    let dltType: Int                 // DLT_ type after activation (127=RadioTap)
    let disassociateResult: Int      // WiFi disassociation result
    let canSetRfmon: Int             // pcap_can_set_rfmon result (1=yes)
    let timeoutCount: Int            // pcap_next_packet returned 0 (timeout)
    let errorCount: Int              // pcap_next_packet returned -1
    let channelHopCount: Int         // Number of channel hops performed
    let pcapStatsRecv: Int           // pcap_stats packets received by kernel
    let pcapStatsDrop: Int           // pcap_stats packets dropped by kernel
    let errbuf: String               // pcap errbuf content
    let injectionSupported: Bool     // pcap_bridge_test_injection result (true = chipset supporta injection)
}

struct MonitorCaptureResult: Codable {
    let beacons: [MonitorBeaconEntry]
    let probeRequests: [MonitorProbeRequestEntry]
    let deauthFrames: [MonitorDeauthEntry]
    let eapolFrames: [MonitorEAPOLEntry]
    let clientAssociations: [MonitorClientAssociation]
    let channelStats: [MonitorChannelStats]
    let hiddenSSIDs: [MonitorHiddenSSID]
    let threatAlerts: [MonitorThreatAlertEntry]
    let signalIntel: [MonitorSignalIntelEntry]
    let totalFrames: Int
    let durationSeconds: Double
    let diagnostics: MonitorCaptureDiagnostics?
    let injectionSupported: Bool     // Risultato test injection (pcap_bridge_test_injection)
}

// MARK: - Operation

class MonitorModeOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    // Aggregated results
    private var beacons: [String: MonitorBeaconEntry] = [:]          // bssid → latest beacon
    private var probeRequests: [String: MonitorProbeRequestEntry] = [:] // mac → aggregated
    private var probeSSIDs: [String: Set<String>] = [:]              // mac → set of SSIDs
    private var deauthFrames: [MonitorDeauthEntry] = []
    private var eapolFrames: [MonitorEAPOLEntry] = []
    private var clientAssociations: [String: MonitorClientAssociation] = [:] // clientMac → assoc
    private var channelStats: [Int: (total: Int, data: Int, mgmt: Int, ctrl: Int)] = [:]
    private var hiddenSSIDs: [String: String] = [:]                  // bssid → revealed SSID
    private var hiddenBSSIDs: Set<String> = []                       // BSSIDs with hidden SSID
    private var totalFrames: Int = 0

    // Threat detection tracking
    private var probeResponseSSIDs: [String: Set<String>] = [:]      // bssid → SSIDs risposte (Karma/MANA)
    private var bssidFirstSeen: [String: Double] = [:]               // bssid → primo timestamp
    private var authFrames: [(bssid: String, sourceMac: String, timestamp: Double)] = []
    private var assocRequestCounts: [String: [(sourceMac: String, timestamp: Double)]] = [:]
    private var probeIESignatures: [String: [UInt8]] = [:]           // sourceMac → IE order
    private var rssiSamples: [String: [(timestamp: Double, rssi: Int)]] = [:] // mac → samples
    private var eapolM1Timestamps: [String: [Double]] = [:]          // bssid → M1 times
    private var eapolM2Timestamps: [String: [Double]] = [:]          // bssid → M2 times

    /// Flag per shutdown graceful: permette al loop di finire il pacchetto corrente
    private var gracefulShutdown = false
    private let shutdownLock = NSLock()

    /// Forza cancellazione base + breakloop pcap (chiamato dopo finestra graceful)
    private func forceStop() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    override func cancel() {
        // Fase 1: segnala shutdown graceful per permettere flush buffer
        shutdownLock.lock()
        gracefulShutdown = true
        shutdownLock.unlock()

        HelperLogger.operations.info("[MonitorMode] Shutdown graceful richiesto, attesa flush buffer (2s)...")

        // Fase 2: attendi breve finestra per flush (2s), poi forza cancellazione
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.forceStop()
            HelperLogger.operations.info("[MonitorMode] Shutdown completato dopo finestra graceful")
        }
    }

    /// Controlla se è richiesto shutdown graceful (usato nel loop pcap)
    var isShuttingDown: Bool {
        shutdownLock.lock()
        defer { shutdownLock.unlock() }
        return gracefulShutdown
    }

    // MARK: - Execute

    func execute(interfaceName: String, channel: Int32, channelHopping: Bool,
                 durationSeconds: Int32) -> Result<Data, Error> {

        HelperLogger.operations.info("[MonitorMode] === INIZIO DIAGNOSTICA ===")
        HelperLogger.operations.info("[MonitorMode] Interfaccia: \(interfaceName), canale: \(channel == 0 ? "hopping" : "\(channel)"), durata: \(durationSeconds)s")

        // Step 1: Disassocia WiFi esplicitamente PRIMA di aprire pcap in monitor mode
        HelperLogger.operations.info("[MonitorMode] Step 1: Dissociazione WiFi...")
        let disassocResult = interfaceName.withCString { iface in
            pcap_bridge_disassociate_wifi(iface)
        }
        HelperLogger.operations.info("[MonitorMode] Dissociazione WiFi: \(disassocResult == 0 ? "OK" : "fallita (\(disassocResult))")")

        // Attendi che il driver completi la dissociazione
        Thread.sleep(forTimeInterval: 0.5)

        // Step 2: Apri pcap in monitor mode con diagnostica estesa
        HelperLogger.operations.info("[MonitorMode] Step 2: Apertura pcap con rfmon...")
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        var activateStatus: Int32 = 0

        let handle = interfaceName.withCString { iface in
            pcap_bridge_open_monitor_ex(iface, 65535, 1000, &errbuf, &activateStatus)
        }

        let errbufStr = String(cString: errbuf)
        if !errbufStr.isEmpty {
            HelperLogger.operations.info("[MonitorMode] pcap errbuf: \(errbufStr)")
        }
        HelperLogger.operations.info("[MonitorMode] pcap_activate status: \(activateStatus) (0=OK, >0=warning, <0=errore)")

        guard let pcap = handle else {
            HelperLogger.forwardError(category: "Operations", message: "FALLITO: pcap_bridge_open_monitor_ex → NULL. Errore: \(errbufStr)", tag: "[MonitorMode]")
            // Ripristina WiFi in caso di fallimento
            interfaceName.withCString { iface in
                _ = pcap_bridge_restore_wifi(iface)
            }
            return .failure(HelperError.pcapError("Monitor mode open fallito: \(errbufStr)"))
        }
        self.pcapHandle = pcap

        // Step 3: Verifica DLT e stato monitor mode
        let dlt = pcap_bridge_datalink(pcap)
        let isMonitor = pcap_bridge_is_monitor_mode(pcap)
        HelperLogger.operations.info("[MonitorMode] Step 3: DLT=\(dlt) (127=RadioTap, 105=802.11), isMonitor=\(isMonitor)")

        defer {
            HelperLogger.operations.info("[MonitorMode] Chiusura pcap e ripristino WiFi...")
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
            // Ripristina WiFi dopo cattura
            interfaceName.withCString { iface in
                _ = pcap_bridge_restore_wifi(iface)
            }
            HelperLogger.operations.info("[MonitorMode] WiFi ripristinato")
        }

        guard isMonitor == 1 else {
            HelperLogger.forwardError(category: "Operations", message: "FALLITO: Interfaccia non in monitor mode (DLT=\(dlt))", tag: "[MonitorMode]")
            return .failure(HelperError.pcapError("Interfaccia non in monitor mode (DLT=\(dlt))"))
        }

        // Step 3b: Test packet injection (chipset Apple integrati non supportano injection)
        let injectionTestResult = pcap_bridge_test_injection(pcap)
        let injectionSupported = (injectionTestResult == 0)
        HelperLogger.operations.info("[MonitorMode] Step 3b: Test injection → \(injectionSupported ? "SUPPORTATA" : "NON supportata") (pcap_sendpacket=\(injectionTestResult))")

        // Step 4: Imposta canale iniziale
        if channel > 0 {
            let chResult = interfaceName.withCString { iface in
                pcap_bridge_set_channel(iface, channel)
            }
            HelperLogger.operations.info("[MonitorMode] Step 4: Set canale \(channel) → \(chResult == 0 ? "OK" : "fallito")")
        } else {
            HelperLogger.operations.info("[MonitorMode] Step 4: Channel hopping attivo (nessun canale fisso)")
        }

        let startTime = Date()
        let deadline = startTime.addingTimeInterval(Double(durationSeconds))

        // Channel hopping setup — solo canali 2.4GHz per massimizzare cattura beacon
        let channels24: [Int32] = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10]
        let channels5: [Int32] = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
        let allChannels = channels24 + channels5
        var channelIndex = 0
        var lastChannelHop = Date()
        let channelHopInterval: TimeInterval = 0.25 // 250ms per channel

        HelperLogger.operations.info("[MonitorMode] Step 5: Inizio cattura frame — deadline \(durationSeconds)s")

        var timeoutCount = 0
        var errorCount = 0
        var lastLogTime = Date()

        while Date() < deadline && !isCancelled && !isShuttingDown {
            // Channel hopping
            if channelHopping && channel == 0 &&
               Date().timeIntervalSince(lastChannelHop) >= channelHopInterval {
                let nextChannel = allChannels[channelIndex % allChannels.count]
                interfaceName.withCString { iface in
                    _ = pcap_bridge_set_channel(iface, nextChannel)
                }
                channelIndex += 1
                lastChannelHop = Date()
            }

            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length > 0 {
                totalFrames += 1
                processFrame(data: packet.data, length: Int(packet.length),
                             timestampUs: packet.timestamp_us)

                // Log primo frame catturato
                if totalFrames == 1 {
                    HelperLogger.operations.info("[MonitorMode] ✓ Primo frame catturato! len=\(packet.length) bytes")
                }
            } else if result == 0 {
                timeoutCount += 1
            } else if result == -1 {
                errorCount += 1
                HelperLogger.forwardError(category: "Operations", message: "pcap_next_packet errore (-1), errorCount=\(errorCount)", tag: "[MonitorMode]")
                if errorCount > 10 { break }
            }

            // Log periodico ogni 5 secondi — invia anche via XPC per console in-app
            if Date().timeIntervalSince(lastLogTime) >= 5.0 {
                let elapsed = Int(Date().timeIntervalSince(startTime))
                let remaining = Int(durationSeconds) - elapsed
                let chLabel = channelHopping ? " ch=\(allChannels[(channelIndex > 0 ? channelIndex - 1 : 0) % allChannels.count])" : ""
                HelperLogger.forwardInfo(
                    category: "Operations",
                    message: "📡 \(self.totalFrames) frame | \(self.beacons.count) AP | \(self.probeRequests.count) probe | \(self.deauthFrames.count) deauth | \(self.clientAssociations.count) client\(chLabel) | -\(remaining)s",
                    tag: "[MonitorMode]"
                )
                lastLogTime = Date()
            }
        }

        let duration = Date().timeIntervalSince(startTime)

        HelperLogger.operations.info("[MonitorMode] === CATTURA COMPLETATA ===")
        HelperLogger.operations.info("[MonitorMode] Totale: \(self.totalFrames) frame in \(String(format: "%.1f", duration))s")
        HelperLogger.operations.info("[MonitorMode] AP: \(self.beacons.count), Probe: \(self.probeRequests.count), Deauth: \(self.deauthFrames.count), EAPOL: \(self.eapolFrames.count)")
        HelperLogger.operations.info("[MonitorMode] Timeout: \(timeoutCount), Errori: \(errorCount), Cancellato: \(self.isCancelled)")
        if totalFrames == 0 {
            HelperLogger.forwardWarning(category: "Operations", message: "ZERO FRAME CATTURATI — monitor mode potrebbe non essere realmente attivo nonostante DLT=\(dlt)", tag: "[MonitorMode]")
        }

        // Kernel-level pcap stats
        var statsRecv: Int32 = -1
        var statsDrop: Int32 = -1
        pcap_bridge_stats(pcap, &statsRecv, &statsDrop)
        HelperLogger.operations.info("[MonitorMode] pcap_stats: recv=\(statsRecv), drop=\(statsDrop)")

        let diag = MonitorCaptureDiagnostics(
            activateStatus: Int(activateStatus),
            dltType: Int(dlt),
            disassociateResult: Int(disassocResult),
            canSetRfmon: 1,
            timeoutCount: timeoutCount,
            errorCount: errorCount,
            channelHopCount: channelIndex,
            pcapStatsRecv: Int(statsRecv),
            pcapStatsDrop: Int(statsDrop),
            errbuf: errbufStr,
            injectionSupported: injectionSupported
        )

        // Analisi minacce post-cattura
        HelperLogger.operations.info("[MonitorMode] Avvio analisi minacce post-cattura...")
        var threatAlerts: [MonitorThreatAlertEntry] = []
        threatAlerts += analyzeEvilTwins()
        threatAlerts += analyzeKarmaAttack()
        threatAlerts += analyzeBeaconFlood()
        threatAlerts += analyzeAssocAuthFlood()
        threatAlerts += analyzePMFVulnerability()
        threatAlerts += analyzePMKIDHarvesting()
        let signalIntel = analyzeSignalIntel()
        HelperLogger.operations.info("[MonitorMode] Analisi completata: \(threatAlerts.count) alert, \(signalIntel.count) signal intel")

        // Build result
        let captureResult = MonitorCaptureResult(
            beacons: Array(beacons.values).sorted { $0.rssi > $1.rssi },
            probeRequests: Array(probeRequests.values).sorted { $0.timestamp > $1.timestamp },
            deauthFrames: deauthFrames,
            eapolFrames: eapolFrames,
            clientAssociations: Array(clientAssociations.values),
            channelStats: channelStats.map { (ch, stats) in
                MonitorChannelStats(channel: ch, totalFrames: stats.total,
                                    dataFrames: stats.data, mgmtFrames: stats.mgmt,
                                    ctrlFrames: stats.ctrl)
            }.sorted { $0.channel < $1.channel },
            hiddenSSIDs: hiddenSSIDs.map { (bssid, ssid) in
                MonitorHiddenSSID(bssid: bssid, revealedSSID: ssid, method: "probe_response")
            },
            threatAlerts: threatAlerts,
            signalIntel: signalIntel,
            totalFrames: totalFrames,
            durationSeconds: duration,
            diagnostics: diag,
            injectionSupported: injectionSupported
        )

        do {
            let jsonData = try JSONEncoder().encode(captureResult)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione MonitorMode fallita: \(error)"))
        }
    }

    // MARK: - Frame Processing

    private func processFrame(data: UnsafePointer<UInt8>, length: Int, timestampUs: Int64) {
        guard length >= 4 else { return }
        let buf = UnsafeBufferPointer(start: data, count: length)

        // Parse RadioTap header
        guard let (radioTapLen, rssi, radioChannel) = parseRadioTapHeader(buf) else { return }
        guard radioTapLen < length else { return }

        let frameStart = radioTapLen
        let frameLen = length - radioTapLen
        guard frameLen >= 2 else { return }

        let timestamp = Double(timestampUs) / 1_000_000.0

        // 802.11 Frame Control (2 bytes, little-endian)
        let fc0 = buf[frameStart]      // Protocol Version + Type + Subtype
        let fc1 = buf[frameStart + 1]  // Flags (ToDS, FromDS, etc.)

        let frameType = fc0 & 0x0C      // bits 2-3
        let frameSubtype = fc0 & 0xF0   // bits 4-7

        // Channel stats
        let ch = radioChannel > 0 ? radioChannel : 0
        var stats = channelStats[ch] ?? (total: 0, data: 0, mgmt: 0, ctrl: 0)
        stats.total += 1

        switch frameType {
        case IEEE80211_TYPE_MANAGEMENT:
            stats.mgmt += 1
            processManagementFrame(buf: buf, frameStart: frameStart, frameLen: frameLen,
                                   subtype: frameSubtype, rssi: rssi, channel: ch,
                                   timestamp: timestamp)
        case IEEE80211_TYPE_CONTROL:
            stats.ctrl += 1
        case IEEE80211_TYPE_DATA:
            stats.data += 1
            processDataFrame(buf: buf, frameStart: frameStart, frameLen: frameLen,
                             fc0: fc0, fc1: fc1, rssi: rssi, timestamp: timestamp)
        default:
            break
        }

        channelStats[ch] = stats
    }

    // MARK: - RadioTap Header

    private func parseRadioTapHeader(_ buf: UnsafeBufferPointer<UInt8>) -> (headerLen: Int, rssi: Int, channel: Int)? {
        guard buf.count >= 8 else { return nil }

        // RadioTap: version (1) + pad (1) + length (2 LE) + present flags (4 LE)
        let version = buf[0]
        guard version == 0 else { return nil } // RadioTap version must be 0

        let headerLen = Int(buf[2]) | (Int(buf[3]) << 8)
        guard headerLen >= 8, headerLen <= buf.count else { return nil }

        let presentFlags = UInt32(buf[4]) | (UInt32(buf[5]) << 8) |
                           (UInt32(buf[6]) << 16) | (UInt32(buf[7]) << 24)

        var offset = 8
        var rssi: Int = -100
        var channel: Int = 0

        // Parse known present fields in order
        // Bit 0: TSFT (8 bytes)
        if presentFlags & (1 << 0) != 0 {
            offset = (offset + 7) & ~7 // align to 8
            offset += 8
        }
        // Bit 1: Flags (1 byte)
        if presentFlags & (1 << 1) != 0 {
            offset += 1
        }
        // Bit 2: Rate (1 byte)
        if presentFlags & (1 << 2) != 0 {
            offset += 1
        }
        // Bit 3: Channel (4 bytes: freq u16 + flags u16)
        if presentFlags & (1 << 3) != 0 {
            offset = (offset + 1) & ~1 // align to 2
            if offset + 4 <= headerLen {
                let freq = Int(buf[offset]) | (Int(buf[offset + 1]) << 8)
                channel = frequencyToChannel(freq)
            }
            offset += 4
        }
        // Bit 4: FHSS (2 bytes)
        if presentFlags & (1 << 4) != 0 {
            offset += 2
        }
        // Bit 5: Antenna Signal dBm (1 byte, signed)
        if presentFlags & (1 << 5) != 0 {
            if offset < headerLen {
                let raw = Int(Int8(bitPattern: buf[offset]))
                // Valori validi WiFi: da -100 a -10 dBm. 0 dBm è impossibile per WiFi
                // e indica che il driver non ha fornito un valore reale.
                if raw < -1 && raw >= -120 {
                    rssi = raw
                }
                // Altrimenti manteniamo il default -100
            }
            offset += 1
        }

        return (headerLen, rssi, channel)
    }

    private func frequencyToChannel(_ freq: Int) -> Int {
        if freq == 2484 { return 14 }
        if freq >= 2412 && freq <= 2472 { return (freq - 2407) / 5 }
        if freq >= 5170 && freq <= 5825 { return (freq - 5000) / 5 }
        if freq >= 5955 && freq <= 7115 { return (freq - 5950) / 5 } // 6 GHz
        return 0
    }

    // MARK: - Management Frames

    private func processManagementFrame(buf: UnsafeBufferPointer<UInt8>,
                                         frameStart: Int, frameLen: Int,
                                         subtype: UInt8, rssi: Int, channel: Int,
                                         timestamp: Double) {
        // Management frame: FC(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtrl(2) = 24 bytes
        guard frameLen >= 24 else { return }

        let addr1 = extractMAC(buf, offset: frameStart + 4)  // Destination
        let addr2 = extractMAC(buf, offset: frameStart + 10) // Source
        let addr3 = extractMAC(buf, offset: frameStart + 16) // BSSID

        let bodyStart = frameStart + 24

        switch subtype {
        case IEEE80211_SUBTYPE_BEACON:
            parseBeaconOrProbeResp(buf: buf, bodyStart: bodyStart, bodyEnd: frameStart + frameLen,
                                   bssid: addr3, rssi: rssi, channel: channel,
                                   timestamp: timestamp, isBeacon: true)

        case IEEE80211_SUBTYPE_PROBE_RESP:
            parseBeaconOrProbeResp(buf: buf, bodyStart: bodyStart, bodyEnd: frameStart + frameLen,
                                   bssid: addr3, rssi: rssi, channel: channel,
                                   timestamp: timestamp, isBeacon: false)
            // Hidden SSID reveal
            if hiddenBSSIDs.contains(addr3) {
                if let ssid = extractSSIDFromIE(buf: buf, bodyStart: bodyStart + 12, bodyEnd: frameStart + frameLen),
                   !ssid.isEmpty {
                    hiddenSSIDs[addr3] = ssid
                }
            }

        case IEEE80211_SUBTYPE_PROBE_REQ:
            parseProbeRequest(buf: buf, bodyStart: bodyStart, bodyEnd: frameStart + frameLen,
                              sourceMac: addr2, rssi: rssi, timestamp: timestamp)

        case IEEE80211_SUBTYPE_DEAUTH:
            parseDeauthFrame(buf: buf, bodyStart: bodyStart, bodyEnd: frameStart + frameLen,
                             sourceMac: addr2, destMac: addr1, bssid: addr3,
                             timestamp: timestamp)

        case IEEE80211_SUBTYPE_DISASSOC:
            parseDeauthFrame(buf: buf, bodyStart: bodyStart, bodyEnd: frameStart + frameLen,
                             sourceMac: addr2, destMac: addr1, bssid: addr3,
                             timestamp: timestamp)

        case IEEE80211_SUBTYPE_AUTH:
            // Traccia auth frame per flood detection
            authFrames.append((bssid: addr3, sourceMac: addr2, timestamp: timestamp))
            recordRSSISample(mac: addr2, timestamp: timestamp, rssi: rssi)

        case IEEE80211_SUBTYPE_ASSOC_REQ:
            // Association reveals hidden SSID
            if let ssid = extractSSIDFromIE(buf: buf, bodyStart: bodyStart + 4, bodyEnd: frameStart + frameLen),
               !ssid.isEmpty, hiddenBSSIDs.contains(addr3) {
                hiddenSSIDs[addr3] = ssid
            }
            // Traccia assoc request per flood detection
            assocRequestCounts[addr3, default: []].append((sourceMac: addr2, timestamp: timestamp))
            recordRSSISample(mac: addr2, timestamp: timestamp, rssi: rssi)

        default:
            break
        }
    }

    // MARK: - Beacon / Probe Response Parsing

    private func parseBeaconOrProbeResp(buf: UnsafeBufferPointer<UInt8>,
                                         bodyStart: Int, bodyEnd: Int,
                                         bssid: String, rssi: Int, channel: Int,
                                         timestamp: Double, isBeacon: Bool) {
        // Fixed fields: Timestamp(8) + Beacon Interval(2) + Capability(2) = 12 bytes
        guard bodyStart + 12 <= bodyEnd else { return }

        let ieStart = bodyStart + 12

        var ssid = ""
        var ieChannel = channel
        var crypto = "Open"
        var htCap = false
        var vhtCap = false
        var wpsEnabled = false
        var pmfCapable = false
        var pmfRequired = false
        var groupCipher = "Unknown"

        // Parse Information Elements
        var offset = ieStart
        while offset + 2 <= bodyEnd {
            let ieID = buf[offset]
            let ieLen = Int(buf[offset + 1])
            let ieDataStart = offset + 2

            guard ieDataStart + ieLen <= bodyEnd else { break }

            switch ieID {
            case 0: // SSID
                if ieLen > 0 {
                    ssid = extractString(buf, offset: ieDataStart, length: ieLen)
                }
            case 3: // DS Parameter Set (channel)
                if ieLen >= 1 {
                    ieChannel = Int(buf[ieDataStart])
                }
            case 45: // HT Capabilities
                htCap = true
            case 48: // RSN (WPA2/WPA3)
                let rsnInfo = parseRSNElement(buf: buf, offset: ieDataStart, length: ieLen)
                crypto = rsnInfo.crypto
                pmfCapable = rsnInfo.pmfCapable
                pmfRequired = rsnInfo.pmfRequired
                groupCipher = rsnInfo.groupCipher
            case 191: // VHT Capabilities
                vhtCap = true
            case 221: // Vendor Specific (WPA1 / WPS)
                if ieLen >= 4 {
                    let oui0 = buf[ieDataStart]
                    let oui1 = buf[ieDataStart + 1]
                    let oui2 = buf[ieDataStart + 2]
                    let ouiType = buf[ieDataStart + 3]
                    // WPA1: OUI 00:50:F2 type 1
                    if oui0 == 0x00 && oui1 == 0x50 && oui2 == 0xF2 && ouiType == 0x01 && crypto == "Open" {
                        crypto = "WPA"
                    }
                    // WPS (Wi-Fi Protected Setup): OUI 00:50:F2 type 4
                    if oui0 == 0x00 && oui1 == 0x50 && oui2 == 0xF2 && ouiType == 0x04 {
                        wpsEnabled = true
                    }
                }
            default:
                break
            }

            offset = ieDataStart + ieLen
        }

        let isHidden = ssid.isEmpty || ssid.allSatisfy({ $0 == "\0" })
        if isHidden {
            hiddenBSSIDs.insert(bssid)
            ssid = "<Hidden>"
        }

        // Traccia primo avvistamento BSSID per beacon flood detection
        if bssidFirstSeen[bssid] == nil {
            bssidFirstSeen[bssid] = timestamp
        }

        // Traccia probe response per Karma/MANA detection
        if !isBeacon && !ssid.isEmpty && ssid != "<Hidden>" {
            probeResponseSSIDs[bssid, default: Set()].insert(ssid)
        }

        // Campiona RSSI per signal intelligence
        recordRSSISample(mac: bssid, timestamp: timestamp, rssi: rssi)

        let isNewAP = beacons[bssid] == nil
        if isBeacon || isNewAP {
            beacons[bssid] = MonitorBeaconEntry(
                bssid: bssid, ssid: ssid, channel: ieChannel, rssi: rssi,
                crypto: crypto, isHidden: isHidden, timestamp: timestamp,
                htCapabilities: htCap, vhtCapabilities: vhtCap,
                wpsEnabled: wpsEnabled,
                pmfCapable: pmfCapable, pmfRequired: pmfRequired,
                groupCipher: groupCipher
            )
            // Log nuovo AP scoperto via XPC
            if isNewAP {
                let label = isHidden ? "[Hidden]" : ssid
                HelperLogger.forwardInfo(
                    category: "Operations",
                    message: "📶 AP: \(label) (\(bssid)) — \(crypto), Ch \(ieChannel), \(rssi) dBm",
                    tag: "[MonitorMode]"
                )
            }
        }
    }

    // MARK: - RSN (WPA2/WPA3) Parsing

    /// Risultato parsing RSN con informazioni PMF e group cipher
    private struct RSNInfo {
        let crypto: String
        let pmfCapable: Bool
        let pmfRequired: Bool
        let groupCipher: String
    }

    private func parseRSNElement(buf: UnsafeBufferPointer<UInt8>, offset: Int, length: Int) -> RSNInfo {
        let defaultInfo = RSNInfo(crypto: "WPA2", pmfCapable: false, pmfRequired: false, groupCipher: "Unknown")
        guard length >= 10 else { return defaultInfo }

        // Version(2) + Group Cipher Suite(4) + Pairwise Cipher Count(2) = 8
        // Group cipher at offset+2..offset+5 (OUI + type)
        var groupCipher = "Unknown"
        if offset + 5 < buf.count && buf[offset + 2] == 0x00 && buf[offset + 3] == 0x0F && buf[offset + 4] == 0xAC {
            switch buf[offset + 5] {
            case 1: groupCipher = "WEP40"
            case 2: groupCipher = "TKIP"
            case 4: groupCipher = "CCMP"
            case 5: groupCipher = "WEP104"
            case 8: groupCipher = "GCMP-128"
            case 9: groupCipher = "GCMP-256"
            default: groupCipher = "Unknown"
            }
        }

        let pairwiseCount = Int(buf[offset + 8]) | (Int(buf[offset + 9]) << 8)
        let akmOffset = offset + 10 + (pairwiseCount * 4)

        guard akmOffset + 2 <= offset + length else {
            return RSNInfo(crypto: "WPA2", pmfCapable: false, pmfRequired: false, groupCipher: groupCipher)
        }

        let akmCount = Int(buf[akmOffset]) | (Int(buf[akmOffset + 1]) << 8)

        var hasWPA3SAE = false
        var hasWPA2PSK = false

        for i in 0..<akmCount {
            let akmBase = akmOffset + 2 + (i * 4)
            guard akmBase + 4 <= offset + length else { break }

            if buf[akmBase] == 0x00 && buf[akmBase + 1] == 0x0F && buf[akmBase + 2] == 0xAC {
                let akmType = buf[akmBase + 3]
                switch akmType {
                case 2: hasWPA2PSK = true
                case 8: hasWPA3SAE = true
                case 18: hasWPA3SAE = true
                default: break
                }
            }
        }

        // RSN Capabilities: 2 bytes dopo le AKM suites
        let rsnCapOffset = akmOffset + 2 + (akmCount * 4)
        var pmfCapable = false
        var pmfRequired = false
        if rsnCapOffset + 2 <= offset + length {
            let rsnCap = UInt16(buf[rsnCapOffset]) | (UInt16(buf[rsnCapOffset + 1]) << 8)
            pmfCapable = (rsnCap & 0x0080) != 0   // bit 7: MFP Capable
            pmfRequired = (rsnCap & 0x0040) != 0   // bit 6: MFP Required
        }

        let crypto: String
        if hasWPA3SAE && hasWPA2PSK { crypto = "WPA3/WPA2" }
        else if hasWPA3SAE { crypto = "WPA3" }
        else { crypto = "WPA2" }

        return RSNInfo(crypto: crypto, pmfCapable: pmfCapable, pmfRequired: pmfRequired, groupCipher: groupCipher)
    }

    // MARK: - Probe Request Parsing

    private func parseProbeRequest(buf: UnsafeBufferPointer<UInt8>,
                                    bodyStart: Int, bodyEnd: Int,
                                    sourceMac: String, rssi: Int, timestamp: Double) {
        var ssids: [String] = []
        var ieIDs: [UInt8] = []

        // Parse IEs for SSID e IE signature (OS fingerprinting)
        var offset = bodyStart
        while offset + 2 <= bodyEnd {
            let ieID = buf[offset]
            let ieLen = Int(buf[offset + 1])
            let ieDataStart = offset + 2
            guard ieDataStart + ieLen <= bodyEnd else { break }

            ieIDs.append(ieID)

            if ieID == 0 && ieLen > 0 {
                let ssid = extractString(buf, offset: ieDataStart, length: ieLen)
                if !ssid.isEmpty && !ssid.allSatisfy({ $0 == "\0" }) {
                    ssids.append(ssid)
                }
            }
            offset = ieDataStart + ieLen
        }

        // Salva IE signature per questo MAC (usata per OS fingerprinting passivo)
        probeIESignatures[sourceMac] = ieIDs

        // Accumulate SSIDs for this MAC
        var existing = probeSSIDs[sourceMac] ?? Set<String>()
        for s in ssids { existing.insert(s) }
        probeSSIDs[sourceMac] = existing

        let isRandomized = isRandomizedMAC(sourceMac)

        // Campiona RSSI
        recordRSSISample(mac: sourceMac, timestamp: timestamp, rssi: rssi)

        probeRequests[sourceMac] = MonitorProbeRequestEntry(
            sourceMac: sourceMac,
            ssidsSearched: Array(existing).sorted(),
            rssi: rssi,
            isRandomizedMAC: isRandomized,
            timestamp: timestamp,
            ieSignature: probeIESignatures[sourceMac] ?? []
        )
    }

    // MARK: - Deauth / Disassoc Parsing

    private func parseDeauthFrame(buf: UnsafeBufferPointer<UInt8>,
                                   bodyStart: Int, bodyEnd: Int,
                                   sourceMac: String, destMac: String, bssid: String,
                                   timestamp: Double) {
        var reasonCode: Int = 0
        if bodyStart + 2 <= bodyEnd {
            reasonCode = Int(buf[bodyStart]) | (Int(buf[bodyStart + 1]) << 8)
        }

        let entry = MonitorDeauthEntry(
            sourceMac: sourceMac,
            destMac: destMac,
            bssid: bssid,
            reasonCode: reasonCode,
            reasonDescription: deauthReasonDescription(reasonCode),
            timestamp: timestamp
        )
        deauthFrames.append(entry)

        // Log deauth in tempo reale (solo i primi 20 per non saturare XPC)
        if deauthFrames.count <= 20 {
            let isBroadcast = destMac == "FF:FF:FF:FF:FF:FF"
            HelperLogger.forwardInfo(
                category: "Operations",
                message: "⚠️ Deauth: \(sourceMac) → \(isBroadcast ? "BROADCAST" : destMac) reason=\(reasonCode)",
                tag: "[MonitorMode]"
            )
        }
    }

    // MARK: - Data Frame Parsing (EAPOL + Client-AP)

    private func processDataFrame(buf: UnsafeBufferPointer<UInt8>,
                                   frameStart: Int, frameLen: Int,
                                   fc0: UInt8, fc1: UInt8, rssi: Int, timestamp: Double) {
        guard frameLen >= 24 else { return }

        let toDS = (fc1 & 0x01) != 0
        let fromDS = (fc1 & 0x02) != 0

        var clientMac = ""
        var apBssid = ""

        // Determine client/AP from To/From DS bits
        // addr1(6), addr2(6), addr3(6)
        let addr1 = extractMAC(buf, offset: frameStart + 4)
        let addr2 = extractMAC(buf, offset: frameStart + 10)
        let addr3 = extractMAC(buf, offset: frameStart + 16)

        if !toDS && fromDS {
            // From AP to client: addr1=DA(client), addr2=BSSID, addr3=SA
            clientMac = addr1
            apBssid = addr2
        } else if toDS && !fromDS {
            // From client to AP: addr1=BSSID, addr2=SA(client), addr3=DA
            clientMac = addr2
            apBssid = addr1
        } else if !toDS && !fromDS {
            // IBSS or same BSS: addr1=DA, addr2=SA, addr3=BSSID
            clientMac = addr2
            apBssid = addr3
        }

        // Record client-AP association
        if !clientMac.isEmpty && !apBssid.isEmpty &&
           clientMac != "FF:FF:FF:FF:FF:FF" && apBssid != "FF:FF:FF:FF:FF:FF" {
            clientAssociations[clientMac] = MonitorClientAssociation(
                clientMac: clientMac, apBssid: apBssid, rssi: rssi, timestamp: timestamp
            )
            recordRSSISample(mac: clientMac, timestamp: timestamp, rssi: rssi)
        }

        // Check for EAPOL (802.1X authentication)
        // Data frame with LLC/SNAP header: AA:AA:03:00:00:00 + EtherType
        let qosLen = (fc0 & 0x80) != 0 ? 2 : 0 // QoS subtype adds 2 bytes
        let llcOffset = frameStart + 24 + qosLen

        guard llcOffset + 8 <= frameStart + frameLen else { return }

        // LLC header: DSAP(0xAA) + SSAP(0xAA) + Control(0x03) + OUI(00:00:00) + EtherType(2)
        if buf[llcOffset] == 0xAA && buf[llcOffset + 1] == 0xAA && buf[llcOffset + 2] == 0x03 {
            let etherType = (UInt16(buf[llcOffset + 6]) << 8) | UInt16(buf[llcOffset + 7])

            if etherType == EAPOL_ETHERTYPE {
                processEAPOLFrame(buf: buf, eapolStart: llcOffset + 8,
                                  eapolEnd: frameStart + frameLen,
                                  sourceMac: addr2, destMac: addr1, bssid: apBssid,
                                  timestamp: timestamp)
            }
        }
    }

    // MARK: - EAPOL Frame Parsing

    private func processEAPOLFrame(buf: UnsafeBufferPointer<UInt8>,
                                    eapolStart: Int, eapolEnd: Int,
                                    sourceMac: String, destMac: String, bssid: String,
                                    timestamp: Double) {
        // EAPOL header: Version(1) + Type(1) + Length(2)
        guard eapolStart + 4 <= eapolEnd else { return }

        let eapolType = buf[eapolStart + 1]
        guard eapolType == 3 else { return } // Type 3 = EAPOL-Key

        // EAPOL-Key: Descriptor Type(1) + Key Info(2) + Key Length(2) + ...
        guard eapolStart + 9 <= eapolEnd else { return }

        let keyInfo = (UInt16(buf[eapolStart + 5]) << 8) | UInt16(buf[eapolStart + 6])
        let messageNumber = identifyEAPOLMessage(keyInfo: keyInfo)

        // Extract raw EAPOL frame as hex for export
        let eapolLen = min(eapolEnd - eapolStart, 512)
        var hexString = ""
        for i in 0..<eapolLen {
            hexString += String(format: "%02x", buf[eapolStart + i])
        }

        let entry = MonitorEAPOLEntry(
            sourceMac: sourceMac,
            destMac: destMac,
            bssid: bssid,
            messageNumber: messageNumber,
            rawHex: hexString,
            timestamp: timestamp
        )
        eapolFrames.append(entry)

        // Traccia M1/M2 per PMKID harvesting detection
        if messageNumber == 1 {
            eapolM1Timestamps[bssid, default: []].append(timestamp)
        } else if messageNumber == 2 {
            eapolM2Timestamps[bssid, default: []].append(timestamp)
        }

        // Log EAPOL in tempo reale — eventi rari e critici, sempre loggati
        HelperLogger.forwardInfo(
            category: "Operations",
            message: "🔑 EAPOL M\(messageNumber) catturato: \(sourceMac) → \(destMac), BSSID: \(bssid)",
            tag: "[MonitorMode]"
        )
    }

    /// Identifica quale dei 4 messaggi del WPA 4-way handshake è questo frame EAPOL-Key
    private func identifyEAPOLMessage(keyInfo: UInt16) -> Int {
        let install = (keyInfo & 0x0040) != 0    // bit 6
        let keyACK  = (keyInfo & 0x0080) != 0    // bit 7
        let keyMIC  = (keyInfo & 0x0100) != 0    // bit 8
        let secure  = (keyInfo & 0x0200) != 0    // bit 9

        if keyACK && !keyMIC {
            return 1  // M1: AP → Client (ANonce, no MIC)
        } else if !keyACK && keyMIC && !install && !secure {
            return 2  // M2: Client → AP (SNonce + MIC)
        } else if keyACK && keyMIC && install && secure {
            return 3  // M3: AP → Client (GTK, install, MIC)
        } else if !keyACK && keyMIC && secure {
            return 4  // M4: Client → AP (ACK)
        }
        return 0 // Unknown
    }

    // MARK: - RSSI Tracking

    private func recordRSSISample(mac: String, timestamp: Double, rssi: Int) {
        var samples = rssiSamples[mac] ?? []
        samples.append((timestamp: timestamp, rssi: rssi))
        // Cap a 100 campioni per MAC
        if samples.count > 100 {
            samples = Array(samples.suffix(100))
        }
        rssiSamples[mac] = samples
    }

    // MARK: - Post-Capture Threat Analysis

    /// Analisi evil twin: stesso SSID, BSSID diversi, crypto/canale diversi
    private func analyzeEvilTwins() -> [MonitorThreatAlertEntry] {
        var alerts: [MonitorThreatAlertEntry] = []
        var ssidGroups: [String: [MonitorBeaconEntry]] = [:]
        for beacon in beacons.values where !beacon.ssid.isEmpty && beacon.ssid != "<Hidden>" {
            ssidGroups[beacon.ssid, default: []].append(beacon)
        }

        for (ssid, group) in ssidGroups where group.count > 1 {
            let sorted = group.sorted { $0.rssi > $1.rssi }
            let legitimate = sorted[0]

            for suspect in sorted.dropFirst() {
                if legitimate.crypto != suspect.crypto {
                    alerts.append(MonitorThreatAlertEntry(
                        type: "evil_twin",
                        severity: "critical",
                        title: "Evil Twin Rilevato: \(ssid)",
                        description: "AP \(suspect.bssid) impersona '\(ssid)' con crypto diversa (\(suspect.crypto) vs \(legitimate.crypto)). Possibile rogue AP per intercettare traffico.",
                        involvedMACs: [legitimate.bssid, suspect.bssid],
                        timestamp: suspect.timestamp
                    ))
                } else if abs(suspect.rssi - legitimate.rssi) < 15 && suspect.channel != legitimate.channel {
                    alerts.append(MonitorThreatAlertEntry(
                        type: "evil_twin",
                        severity: "warning",
                        title: "Possibile Evil Twin: \(ssid)",
                        description: "Due AP con SSID '\(ssid)' su canali diversi (CH\(legitimate.channel) vs CH\(suspect.channel)) con RSSI simile. Verifica se legittimo.",
                        involvedMACs: [legitimate.bssid, suspect.bssid],
                        timestamp: suspect.timestamp
                    ))
                }
            }
        }
        return alerts
    }

    /// Analisi Karma/MANA: AP che risponde a 5+ SSID diversi in probe response
    private func analyzeKarmaAttack() -> [MonitorThreatAlertEntry] {
        var alerts: [MonitorThreatAlertEntry] = []
        for (bssid, ssids) in probeResponseSSIDs where ssids.count >= 5 {
            alerts.append(MonitorThreatAlertEntry(
                type: "karma_mana",
                severity: "critical",
                title: "Attacco Karma/MANA Rilevato",
                description: "AP \(bssid) risponde a \(ssids.count) SSID diversi (\(ssids.prefix(3).joined(separator: ", "))...). Indica un rogue AP che accetta qualsiasi rete richiesta.",
                involvedMACs: [bssid],
                timestamp: Date().timeIntervalSince1970
            ))
        }
        return alerts
    }

    /// Analisi beacon flood: 20+ nuovi BSSID in finestra di 5 secondi
    private func analyzeBeaconFlood() -> [MonitorThreatAlertEntry] {
        var alerts: [MonitorThreatAlertEntry] = []
        let sortedTimes = bssidFirstSeen.values.sorted()
        guard sortedTimes.count >= 20 else { return [] }

        for i in 0..<(sortedTimes.count - 19) {
            let windowStart = sortedTimes[i]
            let windowEnd = sortedTimes[i + 19]
            if windowEnd - windowStart <= 5.0 {
                let floodBSSIDs = bssidFirstSeen.filter { $0.value >= windowStart && $0.value <= windowEnd }.map { $0.key }
                alerts.append(MonitorThreatAlertEntry(
                    type: "beacon_flood",
                    severity: "critical",
                    title: "Beacon Flood Rilevato",
                    description: "\(floodBSSIDs.count) nuovi AP in 5 secondi. Probabile attacco mdk3/mdk4 per saturare la lista WiFi.",
                    involvedMACs: Array(floodBSSIDs.prefix(5)),
                    timestamp: windowStart
                ))
                break // Un solo alert per flood
            }
        }
        return alerts
    }

    /// Analisi auth/assoc flood: 50+ frame verso stesso AP in 10 secondi
    private func analyzeAssocAuthFlood() -> [MonitorThreatAlertEntry] {
        var alerts: [MonitorThreatAlertEntry] = []

        // Auth flood — soglia alta per ridurre falsi positivi
        var authByBSSID: [String: [(sourceMac: String, timestamp: Double)]] = [:]
        for frame in authFrames {
            authByBSSID[frame.bssid, default: []].append((sourceMac: frame.sourceMac, timestamp: frame.timestamp))
        }
        for (bssid, entries) in authByBSSID {
            let timestamps = entries.map { $0.timestamp }
            let uniqueMACs = Set(entries.map { $0.sourceMac }).count
            if detectFloodInTimeSeries(timestamps, window: 10.0, threshold: 100) && uniqueMACs >= 10 {
                alerts.append(MonitorThreatAlertEntry(
                    type: "auth_flood",
                    severity: "critical",
                    title: "Auth Flood Rilevato",
                    description: "\(entries.count) auth frame verso \(bssid) da \(uniqueMACs) MAC diversi. Attacco DoS per esaurire le risorse dell'AP.",
                    involvedMACs: [bssid],
                    timestamp: timestamps.last ?? 0
                ))
            }
        }

        // Assoc flood — soglia alta per ridurre falsi positivi (mesh/extender riconnettono molti client)
        // Richiede 100+ assoc in 10s con almeno 10 MAC diversi (flood usa MAC randomizzati)
        for (bssid, entries) in assocRequestCounts {
            let timestamps = entries.map { $0.timestamp }
            let uniqueMACs = Set(entries.map { $0.sourceMac }).count
            if detectFloodInTimeSeries(timestamps, window: 10.0, threshold: 100) && uniqueMACs >= 10 {
                alerts.append(MonitorThreatAlertEntry(
                    type: "assoc_flood",
                    severity: "critical",
                    title: "Association Flood Rilevato",
                    description: "\(entries.count) assoc request verso \(bssid) da \(uniqueMACs) MAC diversi. Attacco DoS che impedisce nuove connessioni.",
                    involvedMACs: [bssid],
                    timestamp: timestamps.last ?? 0
                ))
            }
        }
        return alerts
    }

    /// Analisi vulnerabilità PMF: AP con crypto ma senza PMF = vulnerabile a deauth
    private func analyzePMFVulnerability() -> [MonitorThreatAlertEntry] {
        var alerts: [MonitorThreatAlertEntry] = []
        for beacon in beacons.values {
            if beacon.crypto != "Open" && beacon.crypto != "WEP" && !beacon.pmfRequired {
                let severity = beacon.pmfCapable ? "info" : "warning"
                let desc = beacon.pmfCapable
                    ? "AP '\(beacon.ssid)' (\(beacon.bssid)) supporta PMF ma non lo richiede. I client senza PMF sono vulnerabili a deauth attack."
                    : "AP '\(beacon.ssid)' (\(beacon.bssid)) non supporta PMF. Tutti i client sono vulnerabili a deauth/disassoc attack."
                alerts.append(MonitorThreatAlertEntry(
                    type: "pmf_vulnerable",
                    severity: severity,
                    title: beacon.pmfCapable ? "PMF Non Obbligatorio: \(beacon.ssid)" : "PMF Assente: \(beacon.ssid)",
                    description: desc,
                    involvedMACs: [beacon.bssid],
                    timestamp: beacon.timestamp
                ))
            }
        }
        return alerts
    }

    /// Analisi PMKID harvesting: 3+ M1 senza M2 completamento in 5 secondi
    private func analyzePMKIDHarvesting() -> [MonitorThreatAlertEntry] {
        var alerts: [MonitorThreatAlertEntry] = []
        for (bssid, m1Times) in eapolM1Timestamps {
            let m2Times = eapolM2Timestamps[bssid] ?? []
            // M1 senza corrispondente M2 entro 5 secondi
            var orphanM1 = 0
            for m1t in m1Times {
                let hasM2 = m2Times.contains { abs($0 - m1t) < 5.0 }
                if !hasM2 { orphanM1 += 1 }
            }
            if orphanM1 >= 3 {
                alerts.append(MonitorThreatAlertEntry(
                    type: "pmkid_harvesting",
                    severity: "critical",
                    title: "PMKID Harvesting Sospetto",
                    description: "\(orphanM1) M1 senza M2 completamento per \(bssid). Possibile attacco PMKID (hcxdumptool) per ottenere hash offline.",
                    involvedMACs: [bssid],
                    timestamp: m1Times.last ?? 0
                ))
            }
        }
        return alerts
    }

    /// Analisi signal intelligence: trend RSSI per MAC
    private func analyzeSignalIntel() -> [MonitorSignalIntelEntry] {
        var results: [MonitorSignalIntelEntry] = []
        for (mac, samples) in rssiSamples where samples.count >= 3 {
            let sorted = samples.sorted { $0.timestamp < $1.timestamp }
            let avgRSSI = sorted.map { $0.rssi }.reduce(0, +) / sorted.count
            let latest = sorted.last!

            // Calcola trend: confronta media prima metà vs seconda metà
            let mid = sorted.count / 2
            let firstHalfAvg = sorted.prefix(mid).map { $0.rssi }.reduce(0, +) / max(mid, 1)
            let secondHalfAvg = sorted.suffix(mid).map { $0.rssi }.reduce(0, +) / max(mid, 1)
            let diff = secondHalfAvg - firstHalfAvg

            let trend: String
            if diff > 5 { trend = "approaching" }
            else if diff < -5 { trend = "departing" }
            else { trend = "stable" }

            results.append(MonitorSignalIntelEntry(
                mac: mac,
                rssiSamples: sorted.map { MonitorRSSISampleEntry(timestamp: $0.timestamp, rssi: $0.rssi) },
                trend: trend,
                averageRSSI: avgRSSI,
                latestRSSI: latest.rssi,
                firstSeen: sorted.first!.timestamp,
                lastSeen: latest.timestamp
            ))
        }
        return results.sorted { $0.latestRSSI > $1.latestRSSI }
    }

    // MARK: - Threat Analysis Helpers

    private func detectFloodInTimeSeries(_ timestamps: [Double], window: Double, threshold: Int) -> Bool {
        guard timestamps.count >= threshold else { return false }
        let sorted = timestamps.sorted()
        for i in 0..<(sorted.count - threshold + 1) {
            if sorted[i + threshold - 1] - sorted[i] <= window {
                return true
            }
        }
        return false
    }

    // MARK: - Helpers

    private func extractMAC(_ buf: UnsafeBufferPointer<UInt8>, offset: Int) -> String {
        guard offset + 6 <= buf.count else { return "00:00:00:00:00:00" }
        return String(format: "%02X:%02X:%02X:%02X:%02X:%02X",
                      buf[offset], buf[offset+1], buf[offset+2],
                      buf[offset+3], buf[offset+4], buf[offset+5])
    }

    private func extractString(_ buf: UnsafeBufferPointer<UInt8>, offset: Int, length: Int) -> String {
        guard offset + length <= buf.count else { return "" }
        let bytes = Array(buf[offset..<(offset + length)])
        return String(bytes: bytes, encoding: .utf8) ?? String(bytes: bytes, encoding: .ascii) ?? ""
    }

    private func extractSSIDFromIE(buf: UnsafeBufferPointer<UInt8>, bodyStart: Int, bodyEnd: Int) -> String? {
        var offset = bodyStart
        while offset + 2 <= bodyEnd {
            let ieID = buf[offset]
            let ieLen = Int(buf[offset + 1])
            let ieDataStart = offset + 2
            guard ieDataStart + ieLen <= bodyEnd else { break }

            if ieID == 0 && ieLen > 0 {
                return extractString(buf, offset: ieDataStart, length: ieLen)
            }
            offset = ieDataStart + ieLen
        }
        return nil
    }

    /// MAC randomizzato: bit 1 del primo ottetto = 1 (locally administered)
    private func isRandomizedMAC(_ mac: String) -> Bool {
        guard let firstByte = UInt8(mac.prefix(2), radix: 16) else { return false }
        return (firstByte & 0x02) != 0
    }

    private func deauthReasonDescription(_ code: Int) -> String {
        switch code {
        case 0: return "Reserved"
        case 1: return "Unspecified reason"
        case 2: return "Previous authentication no longer valid"
        case 3: return "Deauthenticated: leaving BSS"
        case 4: return "Disassociated due to inactivity"
        case 5: return "Disassociated: AP unable to handle all associations"
        case 6: return "Class 2 frame received from non-authenticated station"
        case 7: return "Class 3 frame received from non-associated station"
        case 8: return "Disassociated: leaving BSS"
        case 9: return "Association request rejected: not authenticated"
        case 10: return "Disassociated: power capability unacceptable"
        case 11: return "Disassociated: supported channels unacceptable"
        case 12: return "Reserved"
        case 13: return "Invalid information element"
        case 14: return "MIC failure"
        case 15: return "4-Way Handshake timeout"
        case 16: return "Group Key Handshake timeout"
        case 17: return "Information element differs in 4-Way Handshake"
        case 18: return "Invalid group cipher"
        case 19: return "Invalid pairwise cipher"
        case 20: return "Invalid AKMP"
        case 21: return "Unsupported RSN information element version"
        case 22: return "Invalid RSN information element capabilities"
        case 23: return "IEEE 802.1X authentication failed"
        case 24: return "Cipher suite rejected (security policy)"
        case 34: return "Disassociated: TDLS peer unreachable"
        case 45: return "Peer STA left BSS (or disassociated)"
        case 46: return "Channel switch to operating class/channel"
        default: return "Unknown reason (\(code))"
        }
    }
}
