//
//  raw_socket.c
//  HelperDaemon
//
//  Implementazione wrapper C per raw socket:
//  costruzione pacchetti, checksum, invio/ricezione.
//

// Necessario su macOS per IPV6_RECVHOPLIMIT, IPV6_HOPLIMIT, IPV6_RECVPKTINFO
// Deve essere definito PRIMA di qualsiasi include di sistema
#define __APPLE_USE_RFC_3542

#include "raw_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/time.h>

// MARK: - Checksum

uint16_t ip_checksum(const void *data, int length) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1) {
        sum += *(const uint8_t *)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

uint16_t tcp_checksum(const ip_header_t *ip, const tcp_header_t *tcp,
                      const uint8_t *payload, int payload_len) {
    // Pseudo-header TCP per checksum
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_length;
    } __attribute__((packed)) pseudo;

    int tcp_header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
    int total_tcp_len = tcp_header_len + payload_len;

    pseudo.src_addr = ip->src_addr;
    pseudo.dst_addr = ip->dst_addr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_length = htons(total_tcp_len);

    // Calcola checksum su pseudo-header + TCP header + payload
    int buf_len = sizeof(pseudo) + total_tcp_len;
    // Allinea a multiplo di 2
    uint8_t *buf = (uint8_t *)calloc(1, buf_len + 1);
    if (!buf) return 0;

    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcp, tcp_header_len);
    if (payload && payload_len > 0) {
        memcpy(buf + sizeof(pseudo) + tcp_header_len, payload, payload_len);
    }

    uint16_t result = ip_checksum(buf, buf_len);
    free(buf);
    return result;
}

uint16_t icmp_checksum(const void *data, int length) {
    return ip_checksum(data, length);
}

// MARK: - Raw Socket

int raw_socket_create(int protocol) {
    int sockfd = socket(AF_INET, SOCK_RAW, protocol);
    if (sockfd < 0) {
        return -1;
    }
    return sockfd;
}

int raw_socket_set_hdrincl(int sockfd) {
    int one = 1;
    return setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
}

int raw_socket_set_recv_timeout(int sockfd, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void raw_socket_close(int sockfd) {
    if (sockfd >= 0) {
        close(sockfd);
    }
}

// MARK: - Costruzione Pacchetti

int build_syn_packet(uint8_t *packet, uint32_t src_ip, uint32_t dst_ip,
                     uint16_t src_port, uint16_t dst_port, uint32_t seq_num) {
    memset(packet, 0, 64);

    // Opzioni TCP: MSS (4 byte) + SACK Permitted (2 byte) + NOP (1 byte) + Window Scale (3 byte) + NOP + NOP + Timestamp (10 byte)
    // Totale opzioni: 20 byte → TCP header = 40 byte
    int tcp_options_len = 20;
    int tcp_header_len = 20 + tcp_options_len; // 40 byte
    int total_len = 20 + tcp_header_len;       // 60 byte

    // Header IP
    ip_header_t *ip = (ip_header_t *)packet;
    ip->ihl_version = 0x45;  // IPv4, IHL=5 (20 byte)
    ip->tos = 0;
    ip->total_length = htons(total_len);
    ip->identification = htons(arc4random() & 0xFFFF);
    ip->flags_fragment = htons(0x4000);  // Don't Fragment
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->checksum = 0;
    ip->src_addr = htonl(src_ip);
    ip->dst_addr = htonl(dst_ip);
    ip->checksum = ip_checksum(ip, 20);

    // Header TCP
    tcp_header_t *tcp = (tcp_header_t *)(packet + 20);
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_number = htonl(seq_num);
    tcp->ack_number = 0;
    tcp->data_offset = (tcp_header_len / 4) << 4;  // 10 = 40/4
    tcp->flags = TCP_FLAG_SYN;
    tcp->window_size = htons(65535);
    tcp->checksum = 0;
    tcp->urgent_pointer = 0;

    // Opzioni TCP
    uint8_t *opts = packet + 20 + 20;

    // MSS = 1460
    opts[0] = 2;   // Kind: MSS
    opts[1] = 4;   // Length
    opts[2] = 0x05; // 1460 >> 8
    opts[3] = 0xB4; // 1460 & 0xFF

    // SACK Permitted
    opts[4] = 4;   // Kind: SACK Permitted
    opts[5] = 2;   // Length

    // NOP
    opts[6] = 1;

    // Window Scale = 7
    opts[7] = 3;   // Kind: Window Scale
    opts[8] = 3;   // Length
    opts[9] = 7;   // Shift count

    // NOP + NOP
    opts[10] = 1;
    opts[11] = 1;

    // Timestamp
    opts[12] = 8;  // Kind: Timestamp
    opts[13] = 10; // Length
    uint32_t ts_val = htonl((uint32_t)time(NULL));
    memcpy(opts + 14, &ts_val, 4);
    memset(opts + 18, 0, 4);  // TS echo reply = 0 (SYN)

    // Checksum TCP
    tcp->checksum = tcp_checksum(ip, tcp, NULL, 0);

    return total_len;
}

int build_icmp_echo_packet(uint8_t *packet, uint32_t src_ip, uint32_t dst_ip,
                           uint16_t identifier, uint16_t sequence) {
    memset(packet, 0, 64);

    int icmp_len = 8 + 32;  // header + 32 byte payload
    int total_len = 20 + icmp_len;

    // Header IP
    ip_header_t *ip = (ip_header_t *)packet;
    ip->ihl_version = 0x45;
    ip->tos = 0;
    ip->total_length = htons(total_len);
    ip->identification = htons(arc4random() & 0xFFFF);
    ip->flags_fragment = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->checksum = 0;
    ip->src_addr = htonl(src_ip);
    ip->dst_addr = htonl(dst_ip);
    ip->checksum = ip_checksum(ip, 20);

    // Header ICMP Echo Request
    icmp_header_t *icmp = (icmp_header_t *)(packet + 20);
    icmp->type = 8;       // Echo Request
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->identifier = htons(identifier);
    icmp->sequence = htons(sequence);

    // Payload (timestamp per calcolo RTT)
    uint8_t *payload = packet + 20 + 8;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    memcpy(payload, &tv, sizeof(tv));

    // Checksum ICMP (header + payload)
    icmp->checksum = icmp_checksum(icmp, icmp_len);

    return total_len;
}

int build_arp_request(uint8_t *frame, const uint8_t *src_mac,
                      uint32_t src_ip, uint32_t dst_ip) {
    memset(frame, 0, 42);

    // Header Ethernet
    ethernet_header_t *eth = (ethernet_header_t *)frame;
    memset(eth->dst_mac, 0xFF, 6);  // Broadcast
    memcpy(eth->src_mac, src_mac, 6);
    eth->ether_type = htons(0x0806);  // ARP

    // Header ARP
    arp_header_t *arp = (arp_header_t *)(frame + 14);
    arp->hw_type = htons(1);       // Ethernet
    arp->proto_type = htons(0x0800); // IPv4
    arp->hw_addr_len = 6;
    arp->proto_addr_len = 4;
    arp->opcode = htons(1);        // ARP Request
    memcpy(arp->sender_mac, src_mac, 6);
    arp->sender_ip = htonl(src_ip);
    memset(arp->target_mac, 0, 6);
    arp->target_ip = htonl(dst_ip);

    return 42;  // 14 (Ethernet) + 28 (ARP)
}

// MARK: - Costruzione Frame Ethernet (per pcap injection, bypassa pf)

int build_eth_syn_frame(uint8_t *frame, const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port, uint32_t seq_num) {
    // Ethernet(14) + IP(20) + TCP(40 con opzioni) = 74 byte
    int tcp_options_len = 20;
    int tcp_header_len = 20 + tcp_options_len;  // 40 byte
    int ip_total_len = 20 + tcp_header_len;     // 60 byte
    int frame_len = 14 + ip_total_len;          // 74 byte
    memset(frame, 0, frame_len);

    // Header Ethernet
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x08; frame[13] = 0x00;  // EtherType: IPv4

    // Header IP (offset 14)
    uint8_t *ip_ptr = frame + 14;
    ip_header_t *ip = (ip_header_t *)ip_ptr;
    ip->ihl_version = 0x45;
    ip->tos = 0;
    ip->total_length = htons(ip_total_len);
    ip->identification = htons(arc4random() & 0xFFFF);
    ip->flags_fragment = htons(0x4000);  // Don't Fragment
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->checksum = 0;
    ip->src_addr = htonl(src_ip);
    ip->dst_addr = htonl(dst_ip);
    ip->checksum = ip_checksum(ip, 20);

    // Header TCP (offset 34)
    tcp_header_t *tcp = (tcp_header_t *)(frame + 34);
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_number = htonl(seq_num);
    tcp->ack_number = 0;
    tcp->data_offset = (tcp_header_len / 4) << 4;
    tcp->flags = TCP_FLAG_SYN;
    tcp->window_size = htons(65535);
    tcp->checksum = 0;
    tcp->urgent_pointer = 0;

    // Opzioni TCP (offset 54)
    uint8_t *opts = frame + 54;
    opts[0] = 2; opts[1] = 4; opts[2] = 0x05; opts[3] = 0xB4;  // MSS=1460
    opts[4] = 4; opts[5] = 2;                                     // SACK Permitted
    opts[6] = 1;                                                   // NOP
    opts[7] = 3; opts[8] = 3; opts[9] = 7;                       // Window Scale=7
    opts[10] = 1; opts[11] = 1;                                   // NOP + NOP
    opts[12] = 8; opts[13] = 10;                                  // Timestamp
    uint32_t ts_val = htonl((uint32_t)time(NULL));
    memcpy(opts + 14, &ts_val, 4);
    memset(opts + 18, 0, 4);

    // TCP checksum
    tcp->checksum = tcp_checksum(ip, tcp, NULL, 0);

    return frame_len;
}

int build_eth_rst_frame(uint8_t *frame, const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port, uint32_t seq_num) {
    // Ethernet(14) + IP(20) + TCP(20 minimo) = 54 byte
    int tcp_header_len = 20;
    int ip_total_len = 20 + tcp_header_len;
    int frame_len = 14 + ip_total_len;
    memset(frame, 0, frame_len);

    // Header Ethernet
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x08; frame[13] = 0x00;

    // Header IP
    ip_header_t *ip = (ip_header_t *)(frame + 14);
    ip->ihl_version = 0x45;
    ip->total_length = htons(ip_total_len);
    ip->identification = htons(arc4random() & 0xFFFF);
    ip->flags_fragment = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->checksum = 0;
    ip->src_addr = htonl(src_ip);
    ip->dst_addr = htonl(dst_ip);
    ip->checksum = ip_checksum(ip, 20);

    // Header TCP
    tcp_header_t *tcp = (tcp_header_t *)(frame + 34);
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_number = htonl(seq_num);
    tcp->ack_number = 0;
    tcp->data_offset = (tcp_header_len / 4) << 4;
    tcp->flags = TCP_FLAG_RST | TCP_FLAG_ACK;
    tcp->window_size = 0;
    tcp->checksum = 0;

    tcp->checksum = tcp_checksum(ip, tcp, NULL, 0);

    return frame_len;
}

int build_eth_icmp_frame(uint8_t *frame, const uint8_t *src_mac, const uint8_t *dst_mac,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t identifier, uint16_t sequence) {
    // Ethernet(14) + IP(20) + ICMP(8 + 32 payload) = 74 byte
    int icmp_len = 8 + 32;
    int ip_total_len = 20 + icmp_len;
    int frame_len = 14 + ip_total_len;
    memset(frame, 0, frame_len);

    // Header Ethernet
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x08; frame[13] = 0x00;

    // Header IP
    ip_header_t *ip = (ip_header_t *)(frame + 14);
    ip->ihl_version = 0x45;
    ip->total_length = htons(ip_total_len);
    ip->identification = htons(arc4random() & 0xFFFF);
    ip->flags_fragment = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->checksum = 0;
    ip->src_addr = htonl(src_ip);
    ip->dst_addr = htonl(dst_ip);
    ip->checksum = ip_checksum(ip, 20);

    // Header ICMP
    icmp_header_t *icmp = (icmp_header_t *)(frame + 34);
    icmp->type = 8;       // Echo Request
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->identifier = htons(identifier);
    icmp->sequence = htons(sequence);

    // Payload: timestamp
    uint8_t *payload = frame + 42;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    memcpy(payload, &tv, sizeof(tv));

    // ICMP checksum (header + payload)
    icmp->checksum = icmp_checksum(icmp, icmp_len);

    return frame_len;
}

// MARK: - Costruzione DHCP

int build_dhcp_discover(uint8_t *frame, const uint8_t *src_mac, uint32_t xid) {
    // Frame minimo: Ethernet(14) + IP(20) + UDP(8) + DHCP(300) = 342 byte
    int dhcp_len = 300;  // DHCP base (240) + opzioni (60)
    int udp_len = 8 + dhcp_len;
    int ip_len = 20 + udp_len;
    int total_len = 14 + ip_len;
    memset(frame, 0, total_len);

    // === Ethernet header (14 byte) ===
    memset(frame, 0xFF, 6);             // dst: broadcast
    memcpy(frame + 6, src_mac, 6);      // src: interfaccia locale
    frame[12] = 0x08; frame[13] = 0x00; // ethertype: IPv4

    // === IP header (20 byte) ===
    uint8_t *ip = frame + 14;
    ip[0] = 0x45;              // IPv4, IHL=5
    ip[1] = 0x00;              // TOS
    ip[2] = (ip_len >> 8) & 0xFF;
    ip[3] = ip_len & 0xFF;    // Total length
    ip[4] = (xid >> 8) & 0xFF;
    ip[5] = xid & 0xFF;       // Identification (da xid)
    ip[6] = 0x00; ip[7] = 0x00; // Flags + Fragment
    ip[8] = 128;               // TTL
    ip[9] = 17;                // Protocol: UDP
    ip[10] = 0; ip[11] = 0;   // Checksum (calcolato sotto)
    // Src IP: 0.0.0.0 (DHCPDISCOVER da client senza IP)
    ip[12] = 0; ip[13] = 0; ip[14] = 0; ip[15] = 0;
    // Dst IP: 255.255.255.255 (broadcast)
    ip[16] = 255; ip[17] = 255; ip[18] = 255; ip[19] = 255;
    // Calcola checksum IP
    uint16_t ip_cksum = ip_checksum(ip, 20);
    ip[10] = ip_cksum & 0xFF;
    ip[11] = (ip_cksum >> 8) & 0xFF;

    // === UDP header (8 byte) ===
    uint8_t *udp = ip + 20;
    udp[0] = 0x00; udp[1] = 68;  // Src port: 68 (DHCP client)
    udp[2] = 0x00; udp[3] = 67;  // Dst port: 67 (DHCP server)
    udp[4] = (udp_len >> 8) & 0xFF;
    udp[5] = udp_len & 0xFF;     // UDP length
    udp[6] = 0; udp[7] = 0;      // Checksum (0 = opzionale per IPv4 UDP)

    // === DHCP payload (300 byte) ===
    uint8_t *dhcp = udp + 8;
    dhcp[0] = 1;                  // op: BOOTREQUEST
    dhcp[1] = 1;                  // htype: Ethernet
    dhcp[2] = 6;                  // hlen: 6 (MAC length)
    dhcp[3] = 0;                  // hops
    // xid (byte 4-7)
    dhcp[4] = (xid >> 24) & 0xFF;
    dhcp[5] = (xid >> 16) & 0xFF;
    dhcp[6] = (xid >> 8) & 0xFF;
    dhcp[7] = xid & 0xFF;
    // secs = 0, flags = 0x8000 (broadcast)
    dhcp[8] = 0; dhcp[9] = 0;    // secs
    dhcp[10] = 0x80; dhcp[11] = 0x00; // flags: broadcast
    // ciaddr, yiaddr, siaddr, giaddr = 0 (4 byte ciascuno, offset 12-27)
    // chaddr: MAC client (offset 28-33, padded to 16 byte)
    memcpy(dhcp + 28, src_mac, 6);
    // sname (64 byte, offset 44) e file (128 byte, offset 108) sono zero

    // Magic cookie DHCP (offset 236)
    dhcp[236] = 99; dhcp[237] = 130; dhcp[238] = 83; dhcp[239] = 99;

    // DHCP Options (offset 240+)
    int opt_offset = 240;

    // Option 53: DHCP Message Type = 1 (DISCOVER)
    dhcp[opt_offset++] = 53;  // option
    dhcp[opt_offset++] = 1;   // length
    dhcp[opt_offset++] = 1;   // DHCPDISCOVER

    // Option 55: Parameter Request List
    dhcp[opt_offset++] = 55;  // option
    dhcp[opt_offset++] = 7;   // length
    dhcp[opt_offset++] = 1;   // Subnet Mask
    dhcp[opt_offset++] = 3;   // Router
    dhcp[opt_offset++] = 6;   // DNS Servers
    dhcp[opt_offset++] = 15;  // Domain Name
    dhcp[opt_offset++] = 28;  // Broadcast Address
    dhcp[opt_offset++] = 51;  // Lease Time
    dhcp[opt_offset++] = 54;  // Server Identifier

    // Option 255: End
    dhcp[opt_offset++] = 255;

    return total_len;
}

// MARK: - Parsing Risposte

void parse_tcp_options(const tcp_header_t *tcp_header, int tcp_len,
                       synack_result_t *result) {
    int header_len = ((tcp_header->data_offset >> 4) & 0x0F) * 4;
    int options_len = header_len - 20;

    if (options_len <= 0) return;

    const uint8_t *opts = (const uint8_t *)tcp_header + 20;
    int i = 0;

    result->window_size = ntohs(tcp_header->window_size);
    result->tcp_options_count = 0;
    result->options_order_count = 0;
    result->timestamp_value = 0;

    while (i < options_len) {
        uint8_t kind = opts[i];

        if (kind == 0) break;       // End of Options
        if (kind == 1) { i++; continue; }  // NOP (non contare nell'ordine)

        if (i + 1 >= options_len) break;
        uint8_t len = opts[i + 1];
        if (len < 2 || i + len > options_len) break;

        // Registra ordine delle opzioni (fingerprint OS: MSS→SACK→TS→WS vs MSS→WS→TS→SACK)
        if (result->options_order_count < 12) {
            result->options_order[result->options_order_count++] = kind;
        }

        switch (kind) {
            case 2:  // MSS
                if (len == 4 && i + 3 < options_len) {
                    result->mss = (opts[i + 2] << 8) | opts[i + 3];
                }
                break;

            case 3:  // Window Scale
                if (len == 3 && i + 2 < options_len) {
                    result->window_scaling = opts[i + 2];
                }
                break;

            case 4:  // SACK Permitted
                result->sack_permitted = 1;
                break;

            case 8:  // Timestamp
                result->timestamp_enabled = 1;
                // TSval: 4 byte big-endian a offset i+2
                if (len >= 10 && i + 5 < options_len) {
                    result->timestamp_value =
                        ((uint32_t)opts[i + 2] << 24) |
                        ((uint32_t)opts[i + 3] << 16) |
                        ((uint32_t)opts[i + 4] << 8)  |
                        ((uint32_t)opts[i + 5]);
                }
                break;
        }

        // Salva opzione raw
        if (result->tcp_options_count < 10) {
            result->tcp_options_raw[result->tcp_options_count++] = kind;
        }

        i += len;
    }
}

// MARK: - Utility Interfaccia

int get_interface_ip(const char *interface, char *ip_out) {
    struct ifaddrs *ifap, *ifa;

    if (getifaddrs(&ifap) != 0) {
        return -1;
    }

    int found = -1;
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, interface) != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;

        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &sa->sin_addr, ip_out, INET_ADDRSTRLEN);
        found = 0;
        break;
    }

    freeifaddrs(ifap);
    return found;
}

int get_interface_mac(const char *interface, uint8_t *mac_out) {
    struct ifaddrs *ifap, *ifa;

    if (getifaddrs(&ifap) != 0) {
        return -1;
    }

    int found = -1;
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, interface) != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;

        struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
        if (sdl->sdl_alen == 6) {
            memcpy(mac_out, LLADDR(sdl), 6);
            found = 0;
            break;
        }
    }

    freeifaddrs(ifap);
    return found;
}

// MARK: - IPv6 Raw Socket

int raw_socket_create_v6(int protocol) {
    int sockfd = socket(AF_INET6, SOCK_RAW, protocol);
    if (sockfd < 0) {
        return -1;
    }

    // Abilita ricezione hop limit nei ancillary data (equivalente TTL per IPv6)
    int on = 1;
    setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));

    // Abilita ricezione packet info (dst addr, interface index)
    setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));

    // Solo IPv6 (no dual-stack mapping IPv4)
    setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

    return sockfd;
}

int raw_socket_bind_v6(int sockfd, const char *interface,
                       const struct in6_addr *src_addr) {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_len = sizeof(addr);
    addr.sin6_port = 0;

    if (src_addr) {
        memcpy(&addr.sin6_addr, src_addr, sizeof(struct in6_addr));
    }
    // else: in6addr_any (tutti zeri dopo memset)

    // Scope ID per link-local: necessario per fe80:: addresses
    if (interface) {
        addr.sin6_scope_id = if_nametoindex(interface);
    }

    // Bind anche all'interfaccia via IPV6_BOUND_IF per sicurezza
    if (interface) {
        unsigned int ifindex = if_nametoindex(interface);
        if (ifindex > 0) {
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_BOUND_IF, &ifindex, sizeof(ifindex));
        }
    }

    return bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
}

// MARK: - IPv6 Checksum

uint16_t tcp6_checksum(const struct in6_addr *src, const struct in6_addr *dst,
                       const uint8_t *tcp_segment, int tcp_len) {
    // Pseudo-header IPv6 per TCP (RFC 2460 §8.1):
    // src_addr[16] + dst_addr[16] + upper_layer_length[4] + zero[3] + next_header[1]
    // = 40 byte
    struct __attribute__((packed)) {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t tcp_length;
        uint8_t  zero[3];
        uint8_t  next_header;
    } pseudo;

    memcpy(&pseudo.src, src, sizeof(struct in6_addr));
    memcpy(&pseudo.dst, dst, sizeof(struct in6_addr));
    pseudo.tcp_length = htonl(tcp_len);
    memset(pseudo.zero, 0, 3);
    pseudo.next_header = IPPROTO_TCP;  // 6

    int buf_len = sizeof(pseudo) + tcp_len;
    uint8_t *buf = (uint8_t *)calloc(1, buf_len + 1);  // +1 per allineamento
    if (!buf) return 0;

    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcp_segment, tcp_len);

    uint16_t result = ip_checksum(buf, buf_len);
    free(buf);
    return result;
}

// MARK: - IPv6 Costruzione Pacchetti

int build_tcp_syn_payload(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                          uint32_t seq_num) {
    // Solo TCP header (20B) + opzioni (20B) = 40 byte. NESSUN header IP.
    int tcp_options_len = 20;
    int tcp_header_len = 20 + tcp_options_len;  // 40 byte
    memset(buf, 0, tcp_header_len);

    // Header TCP
    tcp_header_t *tcp = (tcp_header_t *)buf;
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_number = htonl(seq_num);
    tcp->ack_number = 0;
    tcp->data_offset = (tcp_header_len / 4) << 4;  // 10 = 40/4
    tcp->flags = TCP_FLAG_SYN;
    tcp->window_size = htons(65535);
    tcp->checksum = 0;  // Calcolato esternamente con tcp6_checksum()
    tcp->urgent_pointer = 0;

    // Opzioni TCP (identiche a IPv4 SYN, ma MSS=1440 per IPv6 path MTU)
    uint8_t *opts = buf + 20;

    // MSS = 1440 (1500 - 40 IPv6 header - 20 TCP header)
    opts[0] = 2;    // Kind: MSS
    opts[1] = 4;    // Length
    opts[2] = 0x05; // 1440 >> 8
    opts[3] = 0xA0; // 1440 & 0xFF

    // SACK Permitted
    opts[4] = 4;    // Kind: SACK Permitted
    opts[5] = 2;    // Length

    // NOP
    opts[6] = 1;

    // Window Scale = 7
    opts[7] = 3;    // Kind: Window Scale
    opts[8] = 3;    // Length
    opts[9] = 7;    // Shift count

    // NOP + NOP
    opts[10] = 1;
    opts[11] = 1;

    // Timestamp
    opts[12] = 8;   // Kind: Timestamp
    opts[13] = 10;  // Length
    uint32_t ts_val = htonl((uint32_t)time(NULL));
    memcpy(opts + 14, &ts_val, 4);
    memset(opts + 18, 0, 4);  // TS echo reply = 0 (SYN)

    return tcp_header_len;
}

int build_tcp_rst_payload(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                          uint32_t seq_num) {
    // Solo TCP header minimo (20B), nessuna opzione. NESSUN header IP.
    int tcp_header_len = 20;
    memset(buf, 0, tcp_header_len);

    tcp_header_t *tcp = (tcp_header_t *)buf;
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_number = htonl(seq_num);
    tcp->ack_number = 0;
    tcp->data_offset = (tcp_header_len / 4) << 4;  // 5 = 20/4
    tcp->flags = TCP_FLAG_RST | TCP_FLAG_ACK;
    tcp->window_size = 0;
    tcp->checksum = 0;  // Calcolato esternamente con tcp6_checksum()
    tcp->urgent_pointer = 0;

    return tcp_header_len;
}

int build_icmpv6_echo(uint8_t *buf, uint16_t identifier, uint16_t sequence) {
    // ICMPv6 Echo Request: 8 byte header + 32 byte payload = 40 byte
    int payload_size = 32;
    int total_len = 8 + payload_size;
    memset(buf, 0, total_len);

    // ICMPv6 header (type 128 = Echo Request, code 0)
    buf[0] = 128;  // type: Echo Request
    buf[1] = 0;    // code: 0
    buf[2] = 0;    // checksum high (kernel lo calcola per ICMPv6)
    buf[3] = 0;    // checksum low
    buf[4] = (identifier >> 8) & 0xFF;
    buf[5] = identifier & 0xFF;
    buf[6] = (sequence >> 8) & 0xFF;
    buf[7] = sequence & 0xFF;

    // Payload: timestamp per calcolo RTT
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int copy_len = sizeof(tv) < (size_t)payload_size ? (int)sizeof(tv) : payload_size;
    memcpy(buf + 8, &tv, copy_len);

    return total_len;
}

// MARK: - IPv6 Utility Interfaccia

int get_interface_ipv6(const char *interface, char *ip_out, int prefer_global) {
    struct ifaddrs *ifap, *ifa;

    if (getifaddrs(&ifap) != 0) {
        return -1;
    }

    int found_link_local = 0;
    char link_local_buf[INET6_ADDRSTRLEN];

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, interface) != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_INET6) continue;

        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;

        // Skip loopback (::1)
        if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr)) continue;

        // Skip multicast
        if (IN6_IS_ADDR_MULTICAST(&sa6->sin6_addr)) continue;

        // Check flags: skip deprecated/temporary se possibile
        unsigned int flags = ifa->ifa_flags;
        if (flags & IFF_LOOPBACK) continue;

        int is_link_local = IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr);

        if (is_link_local) {
            if (!found_link_local) {
                // Rimuovi scope ID embedded (macOS mette scope ID nel byte 2-3 per link-local)
                struct in6_addr clean_addr = sa6->sin6_addr;
                clean_addr.s6_addr[2] = 0;
                clean_addr.s6_addr[3] = 0;
                inet_ntop(AF_INET6, &clean_addr, link_local_buf, INET6_ADDRSTRLEN);
                found_link_local = 1;
            }

            if (!prefer_global) {
                // Se non preferiamo global, ritorna subito link-local
                struct in6_addr clean_addr = sa6->sin6_addr;
                clean_addr.s6_addr[2] = 0;
                clean_addr.s6_addr[3] = 0;
                inet_ntop(AF_INET6, &clean_addr, ip_out, INET6_ADDRSTRLEN);
                freeifaddrs(ifap);
                return 0;
            }
        } else {
            // Global unicast — ritorna subito (è la scelta preferita)
            inet_ntop(AF_INET6, &sa6->sin6_addr, ip_out, INET6_ADDRSTRLEN);
            freeifaddrs(ifap);
            return 0;
        }
    }

    freeifaddrs(ifap);

    // Fallback: se prefer_global ma solo link-local disponibile, usa quello
    if (found_link_local) {
        strncpy(ip_out, link_local_buf, INET6_ADDRSTRLEN - 1);
        ip_out[INET6_ADDRSTRLEN - 1] = '\0';
        return 0;
    }

    return -1;  // Nessun IPv6 trovato
}

uint32_t get_interface_scope_id(const char *interface) {
    if (!interface) return 0;
    return if_nametoindex(interface);
}

int is_ipv6_address(const char *addr) {
    if (!addr) return 0;
    return (strchr(addr, ':') != NULL) ? 1 : 0;
}

int is_ipv6_link_local(const char *addr) {
    if (!addr) return 0;
    // fe80::/10 → primi 10 bit = 1111 1110 10xx xxxx
    // In pratica: inizia con "fe80:" (case-insensitive)
    if (strncasecmp(addr, "fe80:", 5) == 0 ||
        strncasecmp(addr, "fe80%", 5) == 0) {
        return 1;
    }
    // Verifica anche con parsing completo per edge case
    struct in6_addr a6;
    if (inet_pton(AF_INET6, addr, &a6) == 1) {
        return IN6_IS_ADDR_LINKLOCAL(&a6) ? 1 : 0;
    }
    return 0;
}

int raw_socket_recvmsg_v6(int sockfd, uint8_t *buf, int buf_len,
                          struct sockaddr_in6 *from, int *hop_limit) {
    struct msghdr msg;
    struct iovec iov;
    // Buffer per ancillary data (hop limit + pktinfo)
    uint8_t cmsg_buf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct sockaddr_in6 src_addr;

    memset(&msg, 0, sizeof(msg));
    memset(&src_addr, 0, sizeof(src_addr));
    memset(cmsg_buf, 0, sizeof(cmsg_buf));

    iov.iov_base = buf;
    iov.iov_len = buf_len;

    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(src_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    ssize_t n = recvmsg(sockfd, &msg, 0);
    if (n < 0) {
        return -1;
    }

    // Copia indirizzo sorgente se richiesto
    if (from) {
        memcpy(from, &src_addr, sizeof(struct sockaddr_in6));
    }

    // Estrai hop limit dagli ancillary data
    if (hop_limit) {
        *hop_limit = -1;  // Default: non disponibile
        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
                *hop_limit = *(int *)CMSG_DATA(cmsg);
                break;
            }
        }
    }

    return (int)n;
}
