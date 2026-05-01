//
//  raw_socket.h
//  HelperDaemon
//
//  Wrapper C per raw socket: costruzione pacchetti TCP SYN, ICMP echo,
//  checksum IP/TCP/ICMP, invio e ricezione raw.
//

#ifndef raw_socket_h
#define raw_socket_h

// Necessario su macOS per IPV6_RECVHOPLIMIT, IPV6_HOPLIMIT, IPV6_RECVPKTINFO (RFC 3542)
// Deve essere definito PRIMA di #include <netinet/in.h>
#ifndef __APPLE_USE_RFC_3542
#define __APPLE_USE_RFC_3542
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Fallback: quando Xcode modules pre-includono <netinet/in.h> senza __APPLE_USE_RFC_3542,
// queste costanti RFC 3542 non vengono esportate. Usiamo i valori macOS noti.
#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT  37
#endif
#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT      47
#endif
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO   61
#endif
#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF      125
#endif

// MARK: - Strutture Header

/// Header IP (20 byte senza opzioni)
typedef struct __attribute__((packed)) {
    uint8_t  ihl_version;    // versione (4 bit) + IHL (4 bit)
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} ip_header_t;

/// Header TCP (20 byte senza opzioni)
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t  data_offset;   // offset (4 bit) + reserved (4 bit)
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcp_header_t;

/// Header ICMP (8 byte)
typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} icmp_header_t;

/// Header ARP (28 byte per Ethernet/IPv4)
typedef struct __attribute__((packed)) {
    uint16_t hw_type;        // 0x0001 = Ethernet
    uint16_t proto_type;     // 0x0800 = IPv4
    uint8_t  hw_addr_len;    // 6 per Ethernet
    uint8_t  proto_addr_len; // 4 per IPv4
    uint16_t opcode;         // 1 = request, 2 = reply
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} arp_header_t;

/// Header Ethernet (14 byte)
typedef struct __attribute__((packed)) {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;     // 0x0800 = IP, 0x0806 = ARP
} ethernet_header_t;

/// Risultato SYN-ACK catturato per fingerprinting TCP
typedef struct {
    uint16_t window_size;
    uint16_t mss;
    int      sack_permitted;  // 0 o 1
    int      timestamp_enabled; // 0 o 1
    uint8_t  window_scaling;
    uint8_t  ttl;
    uint32_t tcp_options_raw[10]; // opzioni raw per analisi avanzata
    int      tcp_options_count;
    uint32_t timestamp_value;    // TSval dal SYN-ACK (per clock skew fingerprinting)
    uint8_t  options_order[12];  // Ordine degli option kind nel SYN-ACK (fingerprint OS)
    int      options_order_count;
} synack_result_t;

/// Risultato ICMP ping
typedef struct {
    double   latency_ms;
    uint8_t  ttl;
    uint16_t seq;
    int      received;  // 0 o 1
} icmp_result_t;

// MARK: - Flag TCP

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

// MARK: - Checksum

/// Calcola checksum Internet (RFC 1071)
uint16_t ip_checksum(const void *data, int length);

/// Calcola checksum TCP con pseudo-header
uint16_t tcp_checksum(const ip_header_t *ip, const tcp_header_t *tcp,
                      const uint8_t *payload, int payload_len);

/// Calcola checksum ICMP
uint16_t icmp_checksum(const void *data, int length);

// MARK: - Raw Socket

/// Crea un raw socket per il protocollo specificato.
/// @param protocol IPPROTO_TCP, IPPROTO_ICMP, ecc.
/// @return File descriptor del socket, -1 su errore
int raw_socket_create(int protocol);

/// Abilita IP_HDRINCL sul socket (costruiamo noi l'header IP)
int raw_socket_set_hdrincl(int sockfd);

/// Imposta timeout di ricezione sul socket
int raw_socket_set_recv_timeout(int sockfd, int timeout_ms);

/// Chiude il raw socket
void raw_socket_close(int sockfd);

// MARK: - Costruzione Pacchetti

/// Costruisce un pacchetto TCP SYN completo (IP + TCP + opzioni MSS).
/// @param packet Buffer output (almeno 64 byte)
/// @param src_ip IP sorgente (network byte order)
/// @param dst_ip IP destinazione (network byte order)
/// @param src_port Porta sorgente
/// @param dst_port Porta destinazione
/// @param seq_num Sequence number
/// @return Lunghezza totale del pacchetto
int build_syn_packet(uint8_t *packet, uint32_t src_ip, uint32_t dst_ip,
                     uint16_t src_port, uint16_t dst_port, uint32_t seq_num);

/// Costruisce un pacchetto ICMP Echo Request.
/// @param packet Buffer output (almeno 64 byte)
/// @param src_ip IP sorgente (network byte order)
/// @param dst_ip IP destinazione (network byte order)
/// @param identifier Identificatore ICMP
/// @param sequence Numero sequenza ICMP
/// @return Lunghezza totale del pacchetto
int build_icmp_echo_packet(uint8_t *packet, uint32_t src_ip, uint32_t dst_ip,
                           uint16_t identifier, uint16_t sequence);

/// Costruisce un frame ARP request completo (Ethernet + ARP).
/// @param frame Buffer output (almeno 42 byte)
/// @param src_mac MAC sorgente
/// @param src_ip IP sorgente (network byte order)
/// @param dst_ip IP destinazione (network byte order)
/// @return Lunghezza totale del frame
int build_arp_request(uint8_t *frame, const uint8_t *src_mac,
                      uint32_t src_ip, uint32_t dst_ip);

/// Header UDP (8 byte)
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

// MARK: - Costruzione Frame Ethernet (per pcap injection, bypassa pf)

/// Costruisce un frame Ethernet + IP + TCP SYN completo per invio via pcap.
/// A differenza di build_syn_packet (che è solo IP+TCP per raw socket),
/// questo include l'header Ethernet ed è destinato a pcap_bridge_send_packet().
/// Bypassa pf firewall perché pcap/BPF opera a Layer 2.
/// @param frame Buffer output (almeno 74 byte)
/// @param src_mac MAC sorgente (interfaccia locale)
/// @param dst_mac MAC destinazione (gateway o target per stessa subnet)
/// @param src_ip IP sorgente (host byte order)
/// @param dst_ip IP destinazione (host byte order)
/// @param src_port Porta TCP sorgente
/// @param dst_port Porta TCP destinazione
/// @param seq_num Sequence number
/// @return Lunghezza totale del frame
int build_eth_syn_frame(uint8_t *frame, const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port, uint32_t seq_num);

/// Costruisce un frame Ethernet + IP + TCP RST per chiudere connessioni half-open via pcap.
/// @param frame Buffer output (almeno 54 byte)
/// @param src_mac MAC sorgente
/// @param dst_mac MAC destinazione
/// @param src_ip IP sorgente (host byte order)
/// @param dst_ip IP destinazione (host byte order)
/// @param src_port Porta TCP sorgente
/// @param dst_port Porta TCP destinazione
/// @param seq_num Sequence number
/// @return Lunghezza totale del frame
int build_eth_rst_frame(uint8_t *frame, const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port, uint32_t seq_num);

/// Costruisce un frame Ethernet + IP + ICMP Echo Request completo per invio via pcap.
/// @param frame Buffer output (almeno 74 byte)
/// @param src_mac MAC sorgente
/// @param dst_mac MAC destinazione
/// @param src_ip IP sorgente (host byte order)
/// @param dst_ip IP destinazione (host byte order)
/// @param identifier Identificatore ICMP
/// @param sequence Numero sequenza ICMP
/// @return Lunghezza totale del frame
int build_eth_icmp_frame(uint8_t *frame, const uint8_t *src_mac, const uint8_t *dst_mac,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t identifier, uint16_t sequence);

// MARK: - Costruzione DHCP

/// Costruisce un frame DHCP DISCOVER completo (Ethernet + IP + UDP + DHCP).
/// Frame broadcast L2 per rilevamento server DHCP sulla rete.
/// @param frame Buffer output (almeno 342 byte)
/// @param src_mac MAC sorgente dell'interfaccia
/// @param xid Transaction ID per correlazione request/reply
/// @return Lunghezza totale del frame
int build_dhcp_discover(uint8_t *frame, const uint8_t *src_mac, uint32_t xid);

// MARK: - Parsing Risposte

/// Parsa le opzioni TCP da un SYN-ACK e popola synack_result_t.
/// @param tcp_header Puntatore all'header TCP
/// @param tcp_len Lunghezza totale segmento TCP (header + opzioni)
/// @param result Struttura risultato (output)
void parse_tcp_options(const tcp_header_t *tcp_header, int tcp_len,
                       synack_result_t *result);

/// Ottiene l'indirizzo IP dell'interfaccia specificata.
/// @param interface Nome interfaccia BSD (es. "en0")
/// @param ip_out Buffer output per IP (almeno INET_ADDRSTRLEN)
/// @return 0 su successo, -1 su errore
int get_interface_ip(const char *interface, char *ip_out);

/// Ottiene il MAC address dell'interfaccia specificata.
/// @param interface Nome interfaccia BSD
/// @param mac_out Buffer output per MAC (6 byte)
/// @return 0 su successo, -1 su errore
int get_interface_mac(const char *interface, uint8_t *mac_out);

// MARK: - IPv6 Raw Socket

/// Crea un raw socket IPv6 per il protocollo specificato.
/// Su macOS IPV6_HDRINCL non esiste: il kernel genera sempre l'header IPv6.
/// Noi inviamo solo il payload (TCP/ICMPv6). Il kernel aggiunge l'header IPv6.
/// Setta IPV6_RECVHOPLIMIT per ricevere hop limit nei ancillary data.
/// @param protocol IPPROTO_TCP, IPPROTO_ICMPV6, ecc.
/// @return File descriptor del socket, -1 su errore
int raw_socket_create_v6(int protocol);

/// Associa un socket IPv6 raw a un indirizzo sorgente e interfaccia.
/// Fondamentale: senza bind, il kernel sceglie src addr arbitrariamente.
/// Per link-local (fe80::), setta sin6_scope_id = if_nametoindex(interface).
/// @param sockfd File descriptor del socket
/// @param interface Nome interfaccia BSD (es. "en0")
/// @param src_addr Indirizzo IPv6 sorgente (se NULL, usa INADDR_ANY)
/// @return 0 su successo, -1 su errore
int raw_socket_bind_v6(int sockfd, const char *interface,
                       const struct in6_addr *src_addr);

// MARK: - IPv6 Checksum

/// Calcola checksum TCP con pseudo-header IPv6 (RFC 2460 §8.1).
/// Il kernel non calcola il checksum TCP per raw socket IPv6 — dobbiamo farlo noi.
/// Pseudo-header: src[16] + dst[16] + upper-layer-length[4] + zero[3] + next-header[1]
/// @param src Indirizzo IPv6 sorgente
/// @param dst Indirizzo IPv6 destinazione
/// @param tcp_segment Segmento TCP completo (header + opzioni + payload)
/// @param tcp_len Lunghezza totale del segmento TCP
/// @return Checksum in network byte order
uint16_t tcp6_checksum(const struct in6_addr *src, const struct in6_addr *dst,
                       const uint8_t *tcp_segment, int tcp_len);

// MARK: - IPv6 Costruzione Pacchetti

/// Costruisce SOLO il payload TCP SYN (header + opzioni), SENZA header IPv6.
/// Il kernel aggiunge l'header IPv6 automaticamente su macOS.
/// Include opzioni: MSS(1440) + SACK Permitted + Window Scale(7) + Timestamp.
/// Il campo checksum è lasciato a 0 — va calcolato con tcp6_checksum() e patchato.
/// @param buf Buffer output (almeno 40 byte)
/// @param src_port Porta sorgente
/// @param dst_port Porta destinazione
/// @param seq_num Sequence number
/// @return Lunghezza del payload TCP (tipicamente 40 byte)
int build_tcp_syn_payload(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                          uint32_t seq_num);

/// Costruisce SOLO il payload TCP RST, SENZA header IPv6.
/// Il campo checksum è lasciato a 0 — va calcolato con tcp6_checksum() e patchato.
/// @param buf Buffer output (almeno 20 byte)
/// @param src_port Porta sorgente
/// @param dst_port Porta destinazione
/// @param seq_num Sequence number
/// @return Lunghezza del payload TCP RST (20 byte)
int build_tcp_rst_payload(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                          uint32_t seq_num);

/// Costruisce SOLO il payload ICMPv6 Echo Request, SENZA header IPv6.
/// Il kernel calcola automaticamente il checksum ICMPv6 — mettiamo 0.
/// @param buf Buffer output (almeno 48 byte)
/// @param identifier Identificatore ICMPv6
/// @param sequence Numero sequenza
/// @return Lunghezza del payload ICMPv6 (tipicamente 40 byte: 8 header + 32 data)
int build_icmpv6_echo(uint8_t *buf, uint16_t identifier, uint16_t sequence);

// MARK: - IPv6 Utility Interfaccia

/// Ottiene l'indirizzo IPv6 dell'interfaccia specificata.
/// @param interface Nome interfaccia BSD (es. "en0")
/// @param ip_out Buffer output per IPv6 (almeno INET6_ADDRSTRLEN = 46 byte)
/// @param prefer_global Se 1, preferisce global unicast (2000::/3) su link-local (fe80::/10).
///                      Se 0, ritorna il primo trovato.
/// @return 0 su successo, -1 su errore (nessun IPv6 sull'interfaccia)
int get_interface_ipv6(const char *interface, char *ip_out, int prefer_global);

/// Ottiene il scope_id (interface index) per un'interfaccia BSD.
/// Necessario per sockaddr_in6.sin6_scope_id con indirizzi link-local (fe80::).
/// @param interface Nome interfaccia BSD (es. "en0")
/// @return Interface index (>0 su successo), 0 su errore
uint32_t get_interface_scope_id(const char *interface);

/// Controlla se una stringa è un indirizzo IPv6.
/// Detection rapida: controlla presenza di ':' nella stringa.
/// @param addr Stringa indirizzo IP
/// @return 1 se IPv6, 0 se IPv4 o non valido
int is_ipv6_address(const char *addr);

/// Controlla se un indirizzo IPv6 è link-local (fe80::/10).
/// @param addr Stringa indirizzo IPv6
/// @return 1 se link-local, 0 altrimenti
int is_ipv6_link_local(const char *addr);

/// Riceve dati da un socket IPv6 raw con ancillary data (hop limit).
/// Usa recvmsg() internamente per estrarre IPV6_HOPLIMIT dai cmsg.
/// @param sockfd File descriptor del socket
/// @param buf Buffer output per i dati ricevuti
/// @param buf_len Dimensione del buffer
/// @param from Indirizzo sorgente del pacchetto (output, può essere NULL)
/// @param hop_limit Hop limit ricevuto (output, può essere NULL)
/// @return Numero di byte ricevuti, -1 su errore
int raw_socket_recvmsg_v6(int sockfd, uint8_t *buf, int buf_len,
                          struct sockaddr_in6 *from, int *hop_limit);

#endif /* raw_socket_h */
