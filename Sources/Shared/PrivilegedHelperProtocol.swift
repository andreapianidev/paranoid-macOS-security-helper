//
//  PrivilegedHelperProtocol.swift
//  IPscanner
//
//  Protocollo XPC per le operazioni privilegiate dell'helper daemon.
//  Incluso in entrambi i target (app + helper).
//  Tutti i risultati serializzati come Data (JSON) per evitare NSSecureCoding complesso.
//

import Foundation

/// Protocollo XPC che definisce le operazioni privilegiate dell'helper daemon.
/// Ogni metodo usa `withReply:` per comunicazione asincrona XPC.
/// I risultati sono serializzati come `Data` (JSON) per semplicità.
@objc(PrivilegedHelperProtocol)
protocol PrivilegedHelperProtocol {

    // MARK: - Stato Helper

    /// Verifica che l'helper sia attivo e risponda
    func ping(withReply reply: @escaping (Bool) -> Void)

    /// Restituisce la versione corrente dell'helper
    func getVersion(withReply reply: @escaping (String) -> Void)

    // MARK: - ARP Scan (libpcap)

    /// Esegue un ARP scan sulla subnet specificata usando libpcap.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - startIP: Primo IP del range (es. "192.168.1.1")
    ///   - endIP: Ultimo IP del range (es. "192.168.1.254")
    ///   - timeoutMs: Timeout in millisecondi per l'attesa risposte ARP
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di {ip, mac} oppure errore
    func scanARP(interfaceName: String, startIP: String, endIP: String,
                 timeoutMs: Int32, operationId: String,
                 withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - SYN Scan (raw socket)

    /// Esegue un SYN scan sulle porte specificate usando raw socket TCP.
    /// - Parameters:
    ///   - targetIP: IP dell'host target
    ///   - ports: Lista porte da scansionare (JSON Data con [Int])
    ///   - interfaceName: Nome interfaccia BSD
    ///   - timeoutMs: Timeout per porta in millisecondi
    ///   - maxConcurrent: Numero massimo di SYN in volo contemporaneamente
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di {port, state, latencyMs} oppure errore
    func scanSYN(targetIP: String, ports: Data, interfaceName: String,
                 timeoutMs: Int32, maxConcurrent: Int32, operationId: String,
                 withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - UDP Scan

    /// Esegue un UDP scan sulle porte specificate.
    /// Invia datagram vuoti o payload specifici (DNS/SNMP/NTP) e cattura ICMP port-unreachable.
    /// - Parameters:
    ///   - targetIP: IP dell'host target
    ///   - ports: Lista porte da scansionare (JSON Data con [Int])
    ///   - interfaceName: Nome interfaccia BSD
    ///   - timeoutMs: Timeout per porta in millisecondi
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di {port, state} oppure errore
    func scanUDP(targetIP: String, ports: Data, interfaceName: String,
                 timeoutMs: Int32, operationId: String,
                 withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - ICMP Ping (raw)

    /// Esegue un ICMP echo request/reply raw.
    /// - Parameters:
    ///   - targetIP: IP dell'host target
    ///   - count: Numero di pacchetti ICMP da inviare
    ///   - timeoutMs: Timeout totale in millisecondi
    ///   - interfaceName: Nome interfaccia BSD
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con {latencyMs, ttl, packetLoss} oppure errore
    func pingICMP(targetIP: String, count: Int32, timeoutMs: Int32,
                  interfaceName: String, operationId: String,
                  withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - Passive Discovery (BPF promiscuo)

    /// Cattura passiva del traffico di rete per discovery dispositivi.
    /// Filtra mDNS, SSDP, NetBIOS, DHCP per la durata specificata.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD
    ///   - durationSeconds: Durata cattura in secondi
    ///   - filterTypes: Tipi di traffico da catturare (JSON Data con [String])
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di dispositivi trovati oppure errore
    func passiveDiscovery(interfaceName: String, durationSeconds: Int32,
                          filterTypes: Data, operationId: String,
                          withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - TCP Fingerprint (SYN-ACK capture)

    /// Cattura il SYN-ACK raw per analisi TCP fingerprint (window size, MSS, options).
    /// - Parameters:
    ///   - targetIP: IP dell'host target
    ///   - port: Porta TCP da analizzare
    ///   - interfaceName: Nome interfaccia BSD
    ///   - timeoutMs: Timeout in millisecondi
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con {windowSize, mss, sackPermitted, timestampEnabled, windowScaling, ttl} oppure errore
    func captureSYNACK(targetIP: String, port: Int32, interfaceName: String,
                       timeoutMs: Int32, operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - SYN Monitor (BPF/pcap IDS)

    /// Monitora pacchetti TCP SYN in ingresso tramite BPF/pcap per rilevamento port scan.
    /// Cattura solo SYN puri (no SYN-ACK) diretti al nostro IP per la durata specificata.
    /// Aggrega i risultati: per ogni IP sorgente, l'insieme di porte destinazione colpite.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - durationSeconds: Durata cattura in secondi
    ///   - localIP: IP locale da monitorare (solo SYN diretti a questo IP)
    ///   - portThreshold: Numero minimo di porte distinte per segnalare un port scan
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di {sourceIP, ports: [Int], packetCount} oppure errore
    func monitorIncomingSYN(interfaceName: String, durationSeconds: Int32,
                            localIP: String, portThreshold: Int32,
                            operationId: String,
                            withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - NDP Discovery (IPv6 Neighbor)

    /// Scopre i neighbor IPv6 sulla rete locale tramite ICMPv6 multicast + tabella NDP.
    /// Invia ping6 a ff02::1 (all-nodes link-local) per popolare la tabella NDP,
    /// poi legge ndp -an per raccogliere tutti i neighbor IPv6 con MAC address.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - timeoutSeconds: Timeout totale in secondi per l'operazione
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di {ipv6, mac, isLinkLocal, isRouter} oppure errore
    func discoverNDP(interfaceName: String, timeoutSeconds: Int32,
                     operationId: String,
                     withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - ARP Spoof Detection (pcap)

    /// Monitora ARP reply in tempo reale tramite pcap per rilevare ARP spoofing/MITM.
    /// Mantiene mappa IP→MAC pre-seedata con il gateway e rileva: MAC diverso per gateway,
    /// IP con MAC multipli, MAC flip rapidi (<10s).
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - durationSeconds: Durata cattura in secondi
    ///   - gatewayIP: IP del gateway da monitorare
    ///   - gatewayMAC: MAC legittimo del gateway
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di alert spoofing oppure errore
    func detectARPSpoof(interfaceName: String, durationSeconds: Int32,
                        gatewayIP: String, gatewayMAC: String,
                        operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - Wake-on-LAN (raw L2)

    /// Invia un magic packet Wake-on-LAN come frame Ethernet raw L2 via pcap.
    /// Più affidabile di UDP per device senza IP (sleeping).
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD
    ///   - targetMAC: MAC address del dispositivo da risvegliare (formato "AA:BB:CC:DD:EE:FF")
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con {sent: true, targetMAC} oppure errore
    func sendWakeOnLAN(interfaceName: String, targetMAC: String,
                       operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - ICMP Traceroute (raw socket)

    /// Esegue traceroute ICMP raw, più veloce e preciso del Process-based.
    /// Incrementa TTL da 1 a maxHops, cattura ICMP Time Exceeded e Echo Reply.
    /// - Parameters:
    ///   - targetIP: IP destinazione
    ///   - maxHops: Numero massimo di hop (default 30)
    ///   - timeoutMs: Timeout per singolo probe in millisecondi
    ///   - count: Numero di probe per hop (default 3)
    ///   - interfaceName: Nome interfaccia BSD
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di {hop, ip, latencyMs, timedOut} oppure errore
    func tracerouteICMP(targetIP: String, maxHops: Int32, timeoutMs: Int32,
                        count: Int32, interfaceName: String,
                        operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - Rogue DHCP Detection (pcap)

    /// Invia DHCP DISCOVER broadcast e monitora per server DHCP imprevisti (rogue).
    /// Confronta i server rispondenti con l'expectedServerIP per flag isExpected.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD
    ///   - expectedServerIP: IP del server DHCP legittimo (per confronto)
    ///   - durationSeconds: Durata attesa DHCP OFFER in secondi
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di server DHCP rilevati oppure errore
    func detectRogueDHCP(interfaceName: String, expectedServerIP: String,
                         durationSeconds: Int32, operationId: String,
                         withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - LLDP/CDP Discovery (pcap)

    /// Cattura frame LLDP e CDP per identificare infrastruttura di rete (switch, router, AP).
    /// Rivela: nome switch, porta, VLAN, IP di gestione, capabilities.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD
    ///   - durationSeconds: Durata cattura in secondi (consigliato 60-120s)
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di dispositivi infrastruttura oppure errore
    func discoverLLDP(interfaceName: String, durationSeconds: Int32,
                      operationId: String,
                      withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - HTTP Deep Packet Inspection (BPF/pcap)

    /// Cattura traffico HTTP in chiaro (porta 80) e parsa richieste HTTP.
    /// Estrae metodo, URI, header e body snippet per analisi pattern di attacco (SQLi, XSS, ecc.).
    /// Solo HTTP — HTTPS (porta 443) è cifrato e non ispezionabile senza proxy.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - durationSeconds: Durata cattura in secondi
    ///   - maxBodyBytes: Massimo numero di byte del body da catturare per richiesta
    ///   - port: Porta TCP da monitorare (default 80)
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con HTTPInspectionSessionResult oppure errore
    func inspectHTTP(interfaceName: String, durationSeconds: Int32,
                     maxBodyBytes: Int32, port: Int32,
                     operationId: String,
                     withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - Esecuzione Comandi Generica

    /// Esegue un comando shell arbitrario come root.
    /// Usato per tool esterni (nmap, masscan, bettercap) senza richiedere password ogni volta.
    /// L'output viene scritto in un file temporaneo per streaming real-time dall'app.
    /// - Parameters:
    ///   - path: Path assoluto del binario da eseguire
    ///   - arguments: Argomenti serializzati come JSON Data ([String])
    ///   - environment: Variabili d'ambiente extra serializzate come JSON Data ([String: String]), può essere nil
    ///   - timeoutSeconds: Timeout massimo in secondi
    ///   - outputFile: Path del file temporaneo dove scrivere stdout+stderr per streaming
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con {stdout, stderr, exitCode} oppure errore
    func executeCommand(path: String, arguments: Data, environment: Data?,
                        timeoutSeconds: Int32, outputFile: String,
                        operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - 802.11 Monitor Mode

    /// Avvia cattura frame 802.11 raw in monitor mode (pcap_set_rfmon).
    /// L'interfaccia verrà dissociata dalla rete WiFi corrente per tutta la durata.
    /// Parsa RadioTap + 802.11: beacon, probe req/resp, deauth, EAPOL, data frame.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - channel: Canale WiFi (1-165), 0 per channel hopping automatico
    ///   - channelHopping: Se true, cicla su tutti i canali 2.4/5 GHz
    ///   - durationSeconds: Durata cattura in secondi
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con MonitorCaptureResult oppure errore
    func startMonitorMode(interfaceName: String, channel: Int32,
                          channelHopping: Bool, durationSeconds: Int32,
                          operationId: String,
                          withReply reply: @escaping (Data?, Error?) -> Void)

    /// Ferma la sessione monitor mode in corso (breakloop + chiudi handle).
    /// L'interfaccia en0 si ri-associa automaticamente alla rete WiFi precedente.
    /// - Parameters:
    ///   - operationId: ID dell'operazione monitor da cancellare
    ///   - reply: JSON Data con conferma oppure errore
    func stopMonitorMode(operationId: String,
                         withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - WPA Handshake Capture

    /// Cattura mirata di WPA 4-way handshake per un BSSID target.
    /// State machine EAPOL: M1(ANonce) → M2(SNonce+MIC) → M3(GTK) → M4(ACK).
    /// Opzionalmente invia deauth per forzare ri-autenticazione (inaffidabile su Apple chipset).
    /// Export in .pcap e .hc22000 (Hashcat mode 22000).
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - targetBSSID: BSSID dell'AP target (formato "AA:BB:CC:DD:EE:FF")
    ///   - channel: Canale WiFi dell'AP target
    ///   - sendDeauth: Se true, invia frame deauth per forzare ri-autenticazione
    ///   - clientMAC: MAC del client specifico (nil = qualsiasi client)
    ///   - durationSeconds: Durata massima cattura in secondi
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con HandshakeCaptureResultData oppure errore
    func captureHandshake(interfaceName: String, targetBSSID: String,
                          channel: Int32, sendDeauth: Bool,
                          clientMAC: String?, durationSeconds: Int32,
                          operationId: String,
                          withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - Deauth Attack (Pentesting)

    /// Esegue un attacco deauth standalone verso un AP/client target.
    /// Invia frame deauth IEEE 802.11 via pcap injection in monitor mode.
    /// ATTENZIONE: chipset WiFi Apple potrebbero scartare silenziosamente i frame.
    /// Per injection affidabile usare adattatore WiFi USB esterno.
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - targetBSSID: BSSID dell'AP target (formato "AA:BB:CC:DD:EE:FF")
    ///   - clientMAC: MAC del client target ("FF:FF:FF:FF:FF:FF" per broadcast = tutti i client)
    ///   - channel: Canale WiFi dell'AP target
    ///   - burstCount: Numero di frame deauth per burst
    ///   - intervalMs: Intervallo tra burst in millisecondi
    ///   - reasonCode: Codice motivo deauth IEEE 802.11 (7=Class3, 6=Class2, 1=Unspecified)
    ///   - durationSeconds: Durata totale attacco in secondi
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con {framesSent, framesFailed, durationSeconds} oppure errore
    func sendDeauthAttack(interfaceName: String, targetBSSID: String,
                          clientMAC: String, channel: Int32,
                          burstCount: Int32, intervalMs: Int32,
                          reasonCode: Int32, durationSeconds: Int32,
                          operationId: String,
                          withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - Pcap Port Scan (bypassa pf/VPN kill switch)

    /// Esegue un SYN scan via pcap/BPF che bypassa il firewall pf.
    /// Opera a Layer 2 (Ethernet frame injection), funziona anche con VPN kill switch attivo.
    /// Richiede il MAC del gateway per costruire i frame Ethernet.
    /// - Parameters:
    ///   - targetIP: IP dell'host target
    ///   - ports: Lista porte da scansionare (JSON Data con [Int])
    ///   - interfaceName: Nome interfaccia BSD
    ///   - gatewayMAC: MAC del gateway (formato "AA:BB:CC:DD:EE:FF")
    ///   - timeoutMs: Timeout per porta in millisecondi
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di {port, state, latencyMs} oppure errore
    func pcapScanPorts(targetIP: String, ports: Data, interfaceName: String,
                       gatewayMAC: String, timeoutMs: Int32, operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - Pcap ICMP Ping (bypassa pf/VPN kill switch)

    /// Esegue ICMP ping via pcap/BPF che bypassa il firewall pf.
    /// - Parameters:
    ///   - targetIP: IP dell'host target
    ///   - interfaceName: Nome interfaccia BSD
    ///   - gatewayMAC: MAC del gateway
    ///   - timeoutMs: Timeout in millisecondi
    ///   - count: Numero di pacchetti ICMP
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con {latencyMs, ttl, received} oppure errore
    func pcapPing(targetIP: String, interfaceName: String,
                  gatewayMAC: String, timeoutMs: Int32, count: Int32,
                  operationId: String,
                  withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - ARP Timing (Camera Locator)

    /// Esegue ARP timing ad alta precisione verso target specifici per localizzazione telecamere.
    /// Invia N probe ARP per target e misura RTT Layer 2 con mach_absolute_time().
    /// - Parameters:
    ///   - interfaceName: Nome interfaccia BSD (es. "en0")
    ///   - targetIPs: Lista IP target serializzata come JSON Data ([String])
    ///   - targetMACs: Dizionario IP→MAC serializzato come JSON Data ([String: String])
    ///   - probeCount: Numero di probe ARP per target (default 50)
    ///   - intervalMs: Pausa tra probe in millisecondi (default 100)
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con array di {ip, mac, latenciesMs, sent, received} oppure errore
    func scanARPTiming(interfaceName: String, targetIPs: Data, targetMACs: Data,
                       probeCount: Int32, intervalMs: Int32,
                       operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - DNS Bulk Resolve (v2.0)

    /// Risolve in blocco una lista di IP in hostname con cache integrata.
    /// Il helper mantiene una cache DNS con TTL configurabile per evitare query ridondanti.
    /// - Parameters:
    ///   - ips: Lista IP serializzata come JSON Data ([String])
    ///   - maxConcurrent: Concorrenza massima per le query DNS
    ///   - timeoutPerHost: Timeout per singola risoluzione in secondi
    ///   - operationId: ID univoco per cancellazione
    ///   - reply: JSON Data con {entries: [{ip, hostname?, resolvedAt}], resolvedCount, failedCount, durationMs}
    func bulkDNSResolve(ips: Data, maxConcurrent: Int32,
                        timeoutPerHost: Int32, operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void)

    /// Svuota la cache DNS del helper.
    func flushDNSCache(withReply reply: @escaping (Bool) -> Void)

    // MARK: - Terminal PTY Session

    /// Apre una sessione PTY (pseudo-terminale) come root via forkpty().
    /// L'output (stdout+stderr fusi sul master fd) viene scritto incrementalmente
    /// su `outputFile` per streaming real-time dall'app.
    /// La sessione resta viva finché non viene chiusa con `closePTYSession`,
    /// l'utente termina la shell, oppure scatta il watchdog idle.
    /// - Parameters:
    ///   - shellPath: Path assoluto della shell (es. "/bin/zsh", "/bin/bash"). Validato contro whitelist.
    ///   - arguments: Argomenti shell serializzati come JSON Data ([String]). Tipicamente vuoto o ["-l"].
    ///   - environment: Variabili d'ambiente extra serializzate come JSON Data ([String: String]), può essere vuoto.
    ///   - cols: Colonne iniziali della finestra PTY
    ///   - rows: Righe iniziali della finestra PTY
    ///   - outputFile: Path file dove l'helper appende l'output binario per streaming
    ///   - operationId: ID univoco della sessione (riusato per write/resize/close/cancel)
    ///   - reply: JSON Data con {pid, opened: true} oppure errore
    func openPTYSession(shellPath: String, arguments: Data, environment: Data,
                        cols: Int32, rows: Int32, outputFile: String,
                        operationId: String,
                        withReply reply: @escaping (Data?, Error?) -> Void)

    /// Scrive input grezzo sul master fd di una sessione PTY aperta.
    /// L'app deve includere il terminatore "\n" per inviare un comando.
    /// - Parameters:
    ///   - operationId: ID della sessione PTY ottenuto da `openPTYSession`
    ///   - input: Bytes da scrivere sul master fd
    ///   - reply: JSON Data con {written: Int} oppure errore
    func writePTYInput(operationId: String, input: Data,
                       withReply reply: @escaping (Data?, Error?) -> Void)

    /// Aggiorna le dimensioni della finestra PTY (TIOCSWINSZ).
    /// - Parameters:
    ///   - operationId: ID della sessione PTY
    ///   - cols: Nuove colonne
    ///   - rows: Nuove righe
    func resizePTYSession(operationId: String, cols: Int32, rows: Int32,
                          withReply reply: @escaping (Bool) -> Void)

    /// Chiude una sessione PTY: invia SIGHUP al gruppo di processi e chiude il master fd.
    /// - Parameters:
    ///   - operationId: ID della sessione PTY
    ///   - reply: true se la sessione era attiva ed è stata chiusa
    func closePTYSession(operationId: String,
                         withReply reply: @escaping (Bool) -> Void)

    // MARK: - Honeypot PF Rules (firewall packet filter)

    /// Applica regole pf di blocco IP (anchor "paranoid_block") a un set di IP sorgente.
    /// Le regole sono persistenti finché l'app non chiama `clearHoneypotPF`.
    /// L'helper carica la pf.conf base se non già attiva, crea l'anchor "paranoid_block",
    /// scrive le regole "block drop in quick from <ip>" e ricarica l'anchor.
    /// - Parameters:
    ///   - ipsJSON: JSON Data con array di IP da bloccare ([String])
    ///   - operationId: ID univoco
    ///   - reply: JSON Data con {applied: Int, anchor: String} oppure errore
    func applyPFBlocks(ipsJSON: Data, operationId: String,
                       withReply reply: @escaping (Data?, Error?) -> Void)

    /// Applica regole pf di port redirect (anchor "paranoid_redirect") per dirottare
    /// traffico in ingresso sulle porte standard (22, 23, 80, 443, 3389, 445...) verso
    /// le porte locali dell'honeypot (8022, 8023, 8080, 8443, 13389, 8445...).
    /// Solo per traffico in ingresso da rete locale (en0/en1), non loopback.
    /// - Parameters:
    ///   - redirectsJSON: JSON Data con array di {from: Int, to: Int, iface: String}
    ///   - operationId: ID univoco
    ///   - reply: JSON Data con {applied: Int} oppure errore
    func applyHoneypotRedirects(redirectsJSON: Data, operationId: String,
                                withReply reply: @escaping (Data?, Error?) -> Void)

    /// Rimuove tutte le regole pf gestite dall'app (anchor paranoid_block + paranoid_redirect).
    /// Non tocca pf.conf base né altre anchor.
    /// - Parameters:
    ///   - clearBlocks: Se true, svuota anchor paranoid_block
    ///   - clearRedirects: Se true, svuota anchor paranoid_redirect
    ///   - operationId: ID univoco
    ///   - reply: JSON Data con {cleared: [String]} oppure errore
    func clearHoneypotPF(clearBlocks: Bool, clearRedirects: Bool,
                         operationId: String,
                         withReply reply: @escaping (Data?, Error?) -> Void)

    // MARK: - Cancellazione

    /// Cancella un'operazione in corso identificata dal suo operationId
    func cancelOperation(operationId: String)
}
