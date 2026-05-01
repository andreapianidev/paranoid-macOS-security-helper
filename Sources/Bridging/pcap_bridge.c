//
//  pcap_bridge.c
//  HelperDaemon
//
//  Implementazione wrapper C per libpcap.
//

#include "pcap_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <net/if.h>

// MARK: - Apertura / Chiusura

pcap_t* pcap_bridge_open(const char *interface, int snaplen,
                          int promisc, int timeout_ms, char *errbuf) {
    pcap_t *handle = pcap_open_live(interface, snaplen, promisc, timeout_ms, errbuf);
    if (handle == NULL) {
        return NULL;
    }
    return handle;
}

void pcap_bridge_close(pcap_t *handle) {
    if (handle != NULL) {
        pcap_close(handle);
    }
}

// MARK: - Filtri BPF

int pcap_bridge_set_filter(pcap_t *handle, const char *filter_expr) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

// MARK: - Invio Pacchetti

int pcap_bridge_send_packet(pcap_t *handle, const uint8_t *packet, int length) {
    return pcap_sendpacket(handle, packet, length);
}

int pcap_bridge_test_injection(pcap_t *handle) {
    if (!handle) return -1;

    // Frame 802.11 Null Data minimo con RadioTap header per test injection.
    // Completamente innocuo: broadcast destination, source MAC null.
    uint8_t test_frame[] = {
        // RadioTap header (8 byte, versione 0, nessun campo presente)
        0x00,                               // it_version
        0x00,                               // padding
        0x08, 0x00,                         // it_len (8 byte, little-endian)
        0x00, 0x00, 0x00, 0x00,             // it_present (nessun campo)
        // 802.11 header: Null Data frame (24 byte)
        0x48, 0x00,                         // Frame Control: Data, Null function
        0x00, 0x00,                         // Duration/ID
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Addr1 (destination): broadcast
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Addr2 (source): null
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Addr3 (BSSID): broadcast
        0x00, 0x00                          // Sequence Control
    };

    return pcap_sendpacket(handle, test_frame, sizeof(test_frame));
}

// MARK: - Ricezione Pacchetti

int pcap_bridge_next_packet(pcap_t *handle, pcap_packet_t *packet) {
    struct pcap_pkthdr *header;
    const u_char *data;

    int result = pcap_next_ex(handle, &header, &data);
    if (result == 1) {
        packet->data = data;
        packet->length = (int)header->caplen;
        packet->timestamp_us = (int64_t)header->ts.tv_sec * 1000000LL +
                               (int64_t)header->ts.tv_usec;
    }
    return result;
}

// MARK: - Monitor Mode (802.11)

int pcap_bridge_disassociate_wifi(const char *interface) {
    // Metodo 1: airport -z (dissociazione esplicita, funziona fino a macOS Ventura)
    int ret = system("/System/Library/PrivateFrameworks/Apple80211.framework"
                     "/Versions/Current/Resources/airport -z 2>/dev/null");
    if (ret == 0) return 0;

    // Metodo 2: ifconfig down+up (forza dissociazione su tutte le versioni macOS)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s down 2>/dev/null", interface);
    ret = system(cmd);
    // Piccola pausa per permettere al driver di rilasciare
    usleep(200000); // 200ms
    snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s up 2>/dev/null", interface);
    system(cmd);
    usleep(200000); // 200ms
    return ret;
}

int pcap_bridge_restore_wifi(const char *interface) {
    // Riavvia interfaccia WiFi per ripristinare la connessione dopo monitor mode
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/networksetup -setairportpower %s off 2>/dev/null", interface);
    system(cmd);
    usleep(500000); // 500ms
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/networksetup -setairportpower %s on 2>/dev/null", interface);
    return system(cmd);
}

pcap_t* pcap_bridge_open_monitor(const char *interface, int snaplen,
                                  int timeout_ms, char *errbuf) {
    return pcap_bridge_open_monitor_ex(interface, snaplen, timeout_ms, errbuf, NULL);
}

pcap_t* pcap_bridge_open_monitor_ex(const char *interface, int snaplen,
                                     int timeout_ms, char *errbuf,
                                     int *out_activate_status) {
    pcap_t *handle = pcap_create(interface, errbuf);
    if (handle == NULL) {
        return NULL;
    }

    // Verifica se l'interfaccia supporta rfmon PRIMA di configurare
    int can_rfmon = pcap_can_set_rfmon(handle);
    // can_rfmon: 1=si, 0=no, negativo=errore
    if (can_rfmon == 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                 "Interfaccia %s non supporta monitor mode (pcap_can_set_rfmon=0)",
                 interface);
        pcap_close(handle);
        return NULL;
    }

    if (pcap_set_snaplen(handle, snaplen) != 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_set_snaplen fallito: %s",
                 pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    if (pcap_set_timeout(handle, timeout_ms) != 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_set_timeout fallito: %s",
                 pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    if (pcap_set_rfmon(handle, 1) != 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_set_rfmon fallito: %s",
                 pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    if (pcap_set_promisc(handle, 1) != 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_set_promisc fallito: %s",
                 pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    // Buffer più grande per non perdere frame ad alta velocità
    pcap_set_buffer_size(handle, 4 * 1024 * 1024); // 4MB

    // CRITICO su macOS: immediate mode disabilita il buffering del kernel.
    // Senza questo, pcap_next_ex può restituire timeout (0) anche se ci sono frame
    // perché il kernel aspetta che il buffer si riempia.
    pcap_set_immediate_mode(handle, 1);

    int status = pcap_activate(handle);
    if (out_activate_status) {
        *out_activate_status = status;
    }

    if (status < 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_activate fallito (%d): %s",
                 status, pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    // status > 0 = warning (es. PCAP_WARNING=1) — procediamo ma loggiamo
    if (status > 0) {
        // Scrive il warning in errbuf per il chiamante (non fatale)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_activate warning (%d): %s",
                 status, pcap_geterr(handle));
    }

    int dlt = pcap_datalink(handle);
    if (dlt != DLT_IEEE802_11_RADIO && dlt != DLT_IEEE802_11) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                 "Datalink non 802.11: %d (%s). Monitor mode non attivo.",
                 dlt, pcap_datalink_val_to_name(dlt) ?: "unknown");
        pcap_close(handle);
        return NULL;
    }

    // Tenta di forzare DLT_IEEE802_11_RADIO se disponibile (preferito per RadioTap header)
    if (dlt == DLT_IEEE802_11) {
        pcap_set_datalink(handle, DLT_IEEE802_11_RADIO);
        dlt = pcap_datalink(handle);
    }

    return handle;
}

int pcap_bridge_set_channel(const char *interface, int channel) {
    char cmd[512];
    // Tenta airport (macOS < Sonoma), poi networksetup, poi wdutil
    snprintf(cmd, sizeof(cmd),
             "/System/Library/PrivateFrameworks/Apple80211.framework"
             "/Versions/Current/Resources/airport"
             " --channel=%d 2>/dev/null",
             channel);
    int ret = system(cmd);
    if (ret == 0) return 0;

    // Fallback: apple80211 ioctl via wdutil (macOS Sonoma+)
    snprintf(cmd, sizeof(cmd),
             "/usr/bin/wdutil channel %s %d 2>/dev/null",
             interface, channel);
    ret = system(cmd);
    return (ret == 0) ? 0 : -1;
}

int pcap_bridge_is_monitor_mode(pcap_t *handle) {
    if (handle == NULL) return 0;
    int dlt = pcap_datalink(handle);
    return (dlt == DLT_IEEE802_11_RADIO || dlt == DLT_IEEE802_11) ? 1 : 0;
}

int pcap_bridge_stats(pcap_t *handle, int *recv, int *drop) {
    if (handle == NULL) return -1;
    struct pcap_stat ps;
    if (pcap_stats(handle, &ps) != 0) return -1;
    if (recv) *recv = (int)ps.ps_recv;
    if (drop) *drop = (int)ps.ps_drop;
    return 0;
}

// MARK: - Utility

int pcap_bridge_datalink(pcap_t *handle) {
    return pcap_datalink(handle);
}

void pcap_bridge_breakloop(pcap_t *handle) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

void mac_to_string(const uint8_t *mac, char *out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

uint32_t ip_to_uint32(const char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

void uint32_to_ip(uint32_t ip, char *out) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, out, INET_ADDRSTRLEN);
}
