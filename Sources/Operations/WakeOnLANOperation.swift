//
//  WakeOnLANOperation.swift
//  HelperDaemon
//
//  Operazione Wake-on-LAN tramite frame Ethernet raw L2 via pcap.
//  Costruisce un magic packet (6×0xFF + 16×targetMAC) e lo invia come
//  frame Ethernet broadcast. Più affidabile di UDP per device senza IP.
//  Richiede privilegi root (eseguita dal LaunchDaemon).
//

import Foundation
import os

class WakeOnLANOperation: BaseOperation {

    override func cancel() {
        super.cancel()
    }

    // MARK: - Risultato

    struct WoLResult: Codable {
        let sent: Bool
        let targetMAC: String
    }

    // MARK: - Esecuzione

    /// Invia un magic packet WoL come frame Ethernet raw L2.
    func execute(interfaceName: String, targetMAC: String) -> Result<Data, Error> {

        // Parsa il MAC target dalla stringa "AA:BB:CC:DD:EE:FF"
        let macComponents = targetMAC.uppercased().split(separator: ":").compactMap { UInt8($0, radix: 16) }
        guard macComponents.count == 6 else {
            return .failure(HelperError.invalidParameters("MAC address non valido: \(targetMAC)"))
        }

        // Ottieni MAC sorgente dell'interfaccia
        guard let srcMAC = PacketBuilder.getInterfaceMAC(interfaceName) else {
            return .failure(HelperError.operationFailed("Impossibile ottenere MAC di \(interfaceName)"))
        }

        // Costruisci il magic packet WoL
        // Frame Ethernet: dst=FF:FF:FF:FF:FF:FF, src=localMAC, ethertype=0x0842 (WoL)
        // Payload: 6 byte 0xFF + 16 ripetizioni del target MAC (102 byte)
        var frame = [UInt8](repeating: 0, count: 14 + 102) // Ethernet header + WoL payload

        // Ethernet header (14 byte)
        // Destinazione: broadcast
        for i in 0..<6 { frame[i] = 0xFF }
        // Sorgente: MAC locale
        for i in 0..<6 { frame[6 + i] = srcMAC[i] }
        // EtherType: 0x0842 (Wake-on-LAN)
        frame[12] = 0x08
        frame[13] = 0x42

        // WoL payload: 6 byte 0xFF (sync stream)
        for i in 0..<6 { frame[14 + i] = 0xFF }

        // 16 ripetizioni del target MAC
        for rep in 0..<16 {
            for b in 0..<6 {
                frame[14 + 6 + (rep * 6) + b] = macComponents[b]
            }
        }

        // Apri pcap solo per invio (nessun loop di cattura)
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        let handle = interfaceName.withCString { iface in
            pcap_bridge_open(iface, 64, 0, 100, &errbuf)
        }
        guard let pcap = handle else {
            let errMsg = String(cString: errbuf)
            return .failure(HelperError.pcapError("pcap_open_live WoL fallito: \(errMsg)"))
        }

        defer { pcap_bridge_close(pcap) }

        // Invia il frame
        let sendResult = pcap_bridge_send_packet(pcap, frame, Int32(frame.count))
        guard sendResult == 0 else {
            return .failure(HelperError.operationFailed("Invio magic packet WoL fallito (pcap_sendpacket)"))
        }

        HelperLogger.operations.info("[WoL] Magic packet inviato a \(targetMAC) su \(interfaceName)")

        let result = WoLResult(sent: true, targetMAC: targetMAC)
        do {
            let jsonData = try JSONEncoder().encode(result)
            return .success(jsonData)
        } catch {
            return .failure(HelperError.operationFailed("Serializzazione WoL fallita: \(error)"))
        }
    }
}
