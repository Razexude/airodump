#include <stdio.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "packet.h"
#include "dot11.h"


#define MAC_ADDR_LEN    6
#define ETH_HEADER_SIZE 14   // 6 + 6 + 2
#define ETHERTYPE_IP    0x0800

using namespace wlan;

typedef struct _eth_header {
  uint8_t dst_addr[MAC_ADDR_LEN];
  uint8_t src_addr[MAC_ADDR_LEN];
  uint16_t ether_type;   // next protocol type
} eth_header;


void print_mac_addr(const char *, uint8_t *);
void parse_ip(const u_char*);
void parse_tcp(const u_char*, uint16_t);


void usage(char *fname) {
  printf("syntax: %s <interface>\n", fname);
  printf("sample: %s mon0\n", fname);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage(argv[0]);
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    // printf("%ld   : %u bytes captured\n", header->ts.tv_sec, header->caplen);

    RadiotapHeader* radiotap = (RadiotapHeader*)packet;
    // printf("radiotap length [%hu]\n", radiotap->length);
    Dot11FrameControl* fc = (Dot11FrameControl*)(packet + radiotap->length);
    switch (fc->getTypeSubtype()) {
      case Dot11FC::TypeSubtype::BEACON:
      {
        Dot11BeaconFrame* beacon_frame = (Dot11BeaconFrame*)fc;
        print_mac_addr("mac0 : ", beacon_frame->receiver_addr);
        print_mac_addr("mac1 : ", beacon_frame->transmitter_addr);
        print_mac_addr("mac2 : ", beacon_frame->bssid);
        break;
      }
      default:
        printf("this is not beacon\n");
        break;
    }
  }

  pcap_close(handle);
  return 0;
}

void print_mac_addr(const char *str, uint8_t *a) {
    printf("%s", str);
    for (int i = 0; i < MAC_ADDR_LEN - 1; i++) {
      printf("%02hhX:", a[i]);
    }
    printf("%02hhX\n", a[MAC_ADDR_LEN - 1]);
}

void parse_ip(const u_char* packet) {
    struct ip* ip_header = (struct ip*)packet;
    printf("    src IP   : %s\n", inet_ntoa(ip_header->ip_src));
    printf("    dst IP   : %s\n", inet_ntoa(ip_header->ip_dst));
    
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            {
            // caculate header length : 4bit(& 0xF) and * word(4)
            uint8_t ip_header_len = (ip_header->ip_hl & 0xF) * 4;
            // total length - header length = next protocol lenth
            uint16_t tcp_len = htons(ip_header->ip_len) - ip_header_len;
            parse_tcp(packet + ip_header_len, tcp_len);
            break;
            }
        default:
            printf("Upper proto is not TCP / Protocol : %u\n", ip_header->ip_p);
            break;
    }
}

void parse_tcp(const u_char* packet, uint16_t tcp_len) {
    struct tcphdr* tcp_header = (struct tcphdr*)packet;
    printf("    src port : %hu\n", htons(tcp_header->th_sport));
    printf("    dst port : %hu\n", htons(tcp_header->th_dport));

    // caculate payload lenth
    uint8_t tcp_header_len = ((tcp_header->th_off & 0xF) * 4);
    const u_char* payload = packet + tcp_header_len;
    uint16_t payload_len = tcp_len - tcp_header_len;
    printf("    payload length : %hu\n", payload_len);

    if (payload_len > 0) {
        printf("    DATA : ");
        int print_len = (16 < payload_len) ? 16 : payload_len;
        for (int i = 0; i < print_len; i++) {
            printf("%c", payload[i]);
        }
        puts("");
    }
}
