//
//  HTTPInspectionOperation.swift
//  HelperDaemon
//
//  Operazione di Deep Packet Inspection HTTP tramite BPF/pcap.
//  Cattura traffico TCP porta 80 (HTTP in chiaro) ed estrae:
//  metodo, URI, header, body snippet per analisi pattern di attacco.
//  Solo HTTP — HTTPS (porta 443) è cifrato e non ispezionabile.
//

import Foundation
import os

class HTTPInspectionOperation: BaseOperation {

    private var pcapHandle: OpaquePointer?

    override func cancel() {
        super.cancel()
        if let handle = pcapHandle {
            pcap_bridge_breakloop(handle)
        }
    }

    /// Risultato singola richiesta HTTP catturata
    struct CapturedRequest: Codable {
        let id: String
        let timestamp: Double
        let sourceIP: String
        let destinationIP: String
        let sourcePort: UInt16
        let destinationPort: UInt16
        let method: String
        let uri: String
        let httpVersion: String
        let host: String?
        let userAgent: String?
        let contentType: String?
        let contentLength: Int?
        let headers: [String: String]
        let bodySnippet: String?
        let rawRequestLine: String
    }

    /// Risultato sessione
    struct SessionResult: Codable {
        let requests: [CapturedRequest]
        let durationSeconds: Int
        let totalPacketsCaptured: Int
        let httpPacketsParsed: Int
    }

    /// Esegue cattura HTTP per la durata specificata
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - durationSeconds: Durata cattura in secondi
    ///   - maxBodyBytes: Massimo byte del body da catturare (default 512)
    ///   - port: Porta TCP da monitorare (default 80)
    func execute(interfaceName: String, durationSeconds: Int32,
                 maxBodyBytes: Int32, port: Int32) -> Result<Data, Error> {

        // Filtro BPF: solo TCP sulla porta specificata, solo dati (no SYN/FIN puri)
        let bpfFilter = "tcp port \(port) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) > 0)"

        // Apri pcap (snaplen grande per catturare header + body)
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let snaplen = Int32(min(65535, 1500))  // Snaplen ragionevole
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, snaplen, 0, 100, &errbuf)  // promisc=0 (solo traffico locale)
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("pcap_open_live fallito per HTTP DPI: \(errMsg)"))
        }
        self.pcapHandle = pcap

        defer {
            pcap_bridge_close(pcap)
            self.pcapHandle = nil
        }

        // Imposta filtro BPF
        let filterResult = bpfFilter.withCString { filter in
            pcap_bridge_set_filter(pcap, filter)
        }
        if filterResult != 0 {
            HelperLogger.forwardWarning(category: "Operations", message: "Impossibile impostare filtro BPF: \(bpfFilter)", tag: "[HTTP]")
        }

        var requests: [CapturedRequest] = []
        var totalPackets = 0
        let deadline = Date().addingTimeInterval(Double(durationSeconds))
        let maxBody = Int(maxBodyBytes)

        while Date() < deadline && !isCancelled {
            var packet = pcap_packet_t()
            let result = pcap_bridge_next_packet(pcap, &packet)

            if result == 1 && packet.length > 0 {
                totalPackets += 1
                if let request = parseHTTPPacket(data: packet.data, length: Int(packet.length), maxBody: maxBody) {
                    requests.append(request)
                }
            } else if result == -1 {
                break
            }
        }

        let sessionResult = SessionResult(
            requests: requests,
            durationSeconds: Int(durationSeconds),
            totalPacketsCaptured: totalPackets,
            httpPacketsParsed: requests.count
        )

        do {
            let jsonData = try JSONEncoder().encode(sessionResult)
            HelperLogger.operations.info("[HTTP] Inspection completata: \(requests.count) richieste HTTP su \(totalPackets) pacchetti")
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione HTTP fallita: \(error)"))
        }
    }

    // MARK: - Parsing Pacchetto

    /// Parsa un pacchetto Ethernet → IP → TCP → HTTP
    private func parseHTTPPacket(data: UnsafePointer<UInt8>, length: Int, maxBody: Int) -> CapturedRequest? {
        // Ethernet header: 14 byte
        guard length > 14 + 20 + 20 else { return nil }  // ETH + IP minimo + TCP minimo

        let ethType = (UInt16(data[12]) << 8) | UInt16(data[13])
        guard ethType == 0x0800 else { return nil }  // Solo IPv4

        let ipOffset = 14
        let ipHeaderLen = Int(data[ipOffset] & 0x0F) * 4
        guard ipHeaderLen >= 20 && ipOffset + ipHeaderLen < length else { return nil }

        let protocol_ = data[ipOffset + 9]
        guard protocol_ == 6 else { return nil }  // Solo TCP

        // IP sorgente e destinazione
        let srcIP = "\(data[ipOffset + 12]).\(data[ipOffset + 13]).\(data[ipOffset + 14]).\(data[ipOffset + 15])"
        let dstIP = "\(data[ipOffset + 16]).\(data[ipOffset + 17]).\(data[ipOffset + 18]).\(data[ipOffset + 19])"

        let tcpOffset = ipOffset + ipHeaderLen
        guard tcpOffset + 20 <= length else { return nil }

        let srcPort = (UInt16(data[tcpOffset]) << 8) | UInt16(data[tcpOffset + 1])
        let dstPort = (UInt16(data[tcpOffset + 2]) << 8) | UInt16(data[tcpOffset + 3])
        let tcpHeaderLen = Int((data[tcpOffset + 12] >> 4)) * 4
        guard tcpHeaderLen >= 20 else { return nil }

        let payloadOffset = tcpOffset + tcpHeaderLen
        let payloadLen = length - payloadOffset
        guard payloadLen > 0 else { return nil }

        // Converti payload TCP in stringa
        let payloadData = Data(bytes: data + payloadOffset, count: min(payloadLen, 4096))
        guard let payloadStr = String(data: payloadData, encoding: .utf8) ?? String(data: payloadData, encoding: .ascii) else {
            return nil
        }

        // Verifica che sia una richiesta HTTP (inizia con un metodo HTTP)
        let httpMethods = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "]
        guard httpMethods.contains(where: { payloadStr.hasPrefix($0) }) else { return nil }

        return parseHTTPRequest(payload: payloadStr, srcIP: srcIP, dstIP: dstIP,
                                srcPort: srcPort, dstPort: dstPort, maxBody: maxBody)
    }

    /// Parsa una richiesta HTTP dal payload TCP
    private func parseHTTPRequest(payload: String, srcIP: String, dstIP: String,
                                  srcPort: UInt16, dstPort: UInt16, maxBody: Int) -> CapturedRequest? {
        // Separa header e body
        let headerBodySplit = payload.components(separatedBy: "\r\n\r\n")
        let headerSection = headerBodySplit[0]
        let bodySection = headerBodySplit.count > 1 ? headerBodySplit[1] : nil

        let lines = headerSection.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }

        // Parsa request line: "METHOD URI HTTP/VERSION"
        let parts = requestLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return nil }

        let method = String(parts[0])
        let uri = String(parts[1])
        let httpVersion = parts.count > 2 ? String(parts[2]) : "HTTP/1.1"

        // Parsa header
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            if let colonIdx = line.firstIndex(of: ":") {
                let key = String(line[line.startIndex..<colonIdx]).trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                headers[key] = value
            }
        }

        // Estrai header comuni
        let host = headers["Host"]
        let userAgent = headers["User-Agent"]
        let contentType = headers["Content-Type"]
        let contentLength = headers["Content-Length"].flatMap { Int($0) }

        // Body snippet (limitato)
        var bodySnippet: String? = nil
        if let body = bodySection, !body.isEmpty {
            bodySnippet = String(body.prefix(maxBody))
        }

        return CapturedRequest(
            id: UUID().uuidString,
            timestamp: Date().timeIntervalSince1970,
            sourceIP: srcIP,
            destinationIP: dstIP,
            sourcePort: srcPort,
            destinationPort: dstPort,
            method: method,
            uri: uri,
            httpVersion: httpVersion,
            host: host,
            userAgent: userAgent,
            contentType: contentType,
            contentLength: contentLength,
            headers: headers,
            bodySnippet: bodySnippet,
            rawRequestLine: requestLine
        )
    }
}
