//
//  pcap_bridge.h
//  HelperDaemon
//
//  Wrapper C per libpcap: apertura interfaccia, filtri BPF,
//  invio/ricezione pacchetti per ARP scan e passive discovery.
//

#ifndef pcap_bridge_h
#define pcap_bridge_h

#include <stdint.h>
#include <pcap/pcap.h>

// MARK: - Strutture risultato

/// Risultato di un singolo pacchetto catturato
typedef struct {
    const uint8_t *data;
    int length;
    int64_t timestamp_us;  // microseconds since epoch
} pcap_packet_t;

/// Entry ARP trovata
typedef struct {
    char ip[16];           // IPv4 dotted notation
    uint8_t mac[6];        // MAC address raw
    char mac_str[18];      // MAC address "AA:BB:CC:DD:EE:FF"
} arp_entry_t;

// MARK: - Apertura / Chiusura

/// Apre un'interfaccia di rete per cattura pcap.
/// @param interface Nome interfaccia BSD (es. "en0")
/// @param snaplen Lunghezza massima cattura per pacchetto
/// @param promisc 1 per modalità promiscua, 0 altrimenti
/// @param timeout_ms Timeout read in millisecondi
/// @param errbuf Buffer per messaggi di errore (almeno PCAP_ERRBUF_SIZE)
/// @return Handle pcap o NULL in caso di errore
pcap_t* pcap_bridge_open(const char *interface, int snaplen,
                          int promisc, int timeout_ms, char *errbuf);

/// Chiude l'handle pcap
void pcap_bridge_close(pcap_t *handle);

// MARK: - Filtri BPF

/// Imposta un filtro BPF sull'handle pcap.
/// @param handle Handle pcap
/// @param filter_expr Espressione filtro BPF (es. "arp")
/// @return 0 su successo, -1 su errore
int pcap_bridge_set_filter(pcap_t *handle, const char *filter_expr);

// MARK: - Invio Pacchetti

/// Invia un pacchetto raw sull'interfaccia.
/// @param handle Handle pcap
/// @param packet Dati del pacchetto
/// @param length Lunghezza del pacchetto
/// @return 0 su successo, -1 su errore
int pcap_bridge_send_packet(pcap_t *handle, const uint8_t *packet, int length);

/// Testa se l'interfaccia in monitor mode supporta packet injection.
/// Invia un frame 802.11 null data minimo via pcap_sendpacket.
/// I chipset WiFi Apple integrati non supportano injection (ritorna -1).
/// @param handle Handle pcap in monitor mode
/// @return 0 se injection supportata, -1 se non supportata
int pcap_bridge_test_injection(pcap_t *handle);

// MARK: - Ricezione Pacchetti

/// Riceve il prossimo pacchetto dall'interfaccia.
/// @param handle Handle pcap
/// @param packet Struttura pacchetto risultato (output)
/// @return 1 se pacchetto ricevuto, 0 timeout, -1 errore, -2 EOF
int pcap_bridge_next_packet(pcap_t *handle, pcap_packet_t *packet);

// MARK: - Monitor Mode (802.11)

/// Disassocia l'interfaccia WiFi dalla rete corrente (preparazione per monitor mode).
/// Tenta airport -z, poi ifconfig down/up come fallback.
/// @param interface Nome interfaccia BSD (es. "en0")
/// @return 0 su successo
int pcap_bridge_disassociate_wifi(const char *interface);

/// Ripristina l'interfaccia WiFi dopo monitor mode (power cycle via networksetup).
/// @param interface Nome interfaccia BSD
/// @return 0 su successo
int pcap_bridge_restore_wifi(const char *interface);

/// Apre un'interfaccia in monitor mode per cattura frame 802.11 raw.
/// Usa pcap_create → pcap_set_rfmon(1) → pcap_activate (non pcap_open_live).
/// Il datalink risultante sarà DLT_IEEE802_11_RADIO (RadioTap + 802.11).
/// NOTA: Richiede root. Chiamare pcap_bridge_disassociate_wifi prima.
/// @param interface Nome interfaccia BSD (es. "en0")
/// @param snaplen Lunghezza massima cattura per pacchetto (consigliato 65535)
/// @param timeout_ms Timeout read in millisecondi
/// @param errbuf Buffer per messaggi di errore (almeno PCAP_ERRBUF_SIZE)
/// @return Handle pcap in monitor mode, o NULL in caso di errore
pcap_t* pcap_bridge_open_monitor(const char *interface, int snaplen,
                                  int timeout_ms, char *errbuf);

/// Versione estesa di pcap_bridge_open_monitor con status di attivazione in output.
/// @param out_activate_status Puntatore dove scrivere il codice ritorno di pcap_activate (può essere NULL)
pcap_t* pcap_bridge_open_monitor_ex(const char *interface, int snaplen,
                                     int timeout_ms, char *errbuf,
                                     int *out_activate_status);

/// Imposta il canale WiFi sull'interfaccia via airport/wdutil.
/// @param interface Nome interfaccia BSD
/// @param channel Numero canale (1-165)
/// @return 0 su successo, -1 su errore
int pcap_bridge_set_channel(const char *interface, int channel);

/// Verifica se l'handle pcap è in modalità monitor (DLT_IEEE802_11_RADIO).
/// @param handle Handle pcap
/// @return 1 se monitor mode (RadioTap), 0 altrimenti
int pcap_bridge_is_monitor_mode(pcap_t *handle);

/// Ottiene le statistiche pcap (pacchetti ricevuti/droppati dal kernel).
/// @param handle Handle pcap
/// @param recv Output: pacchetti ricevuti
/// @param drop Output: pacchetti droppati
/// @return 0 su successo, -1 su errore
int pcap_bridge_stats(pcap_t *handle, int *recv, int *drop);

// MARK: - Utility

/// Ottiene il datalink type dell'interfaccia
int pcap_bridge_datalink(pcap_t *handle);

/// Interrompe il loop pcap (thread-safe)
void pcap_bridge_breakloop(pcap_t *handle);

/// Converte un indirizzo MAC raw in stringa "AA:BB:CC:DD:EE:FF"
void mac_to_string(const uint8_t *mac, char *out);

/// Converte un indirizzo IPv4 in network byte order
uint32_t ip_to_uint32(const char *ip);

/// Converte un uint32 network byte order in stringa IPv4
void uint32_to_ip(uint32_t ip, char *out);

#endif /* pcap_bridge_h */
