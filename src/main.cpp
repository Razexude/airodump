#include <stdio.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>

#include <vector>
#include <string>

#include "MacAddr.h"
#include "dot11.h"
#include "util.h"
#include "my_radiotap.h"
#include "AirodumpApInfo.h"

using namespace wlan;


void usage(char *fname) {
  printf("syntax: %s <interface>\n", fname);
  printf("sample: %s mon0\n", fname);
}

// map으로 하려다가... MacAddr을 key로 사용하려면 operator<도 오버로딩 해야하고 번거로워서. 컨테이너 규모가 작으면 vector가 더 빠르기도 하고.
std::vector<AirodumpApInfo> ap_list;
// std::vector<AirodumpStationInfo> station_list;


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
    if (fc->getTypeSubtype() == Dot11FC::TypeSubtype::BEACON) {
      Dot11BeaconFrame* beacon_frame = (Dot11BeaconFrame*)fc;
      std::cout << beacon_frame->bssid << std::endl;
      printf("type[%x]channel[%x]\n",
                                fc->getTypeSubtype(), 
                                *(int16_t*)radiotap->getField(PresentFlag::CHANNEL));

      auto exist = false;
      for (auto ap_info = ap_list.begin(); ap_info != ap_list.end(); ++ap_info) {
        if (ap_info->bssid == beacon_frame->bssid) {
          exist = true;
          // printf("이미 있는거네!\n");
          ap_info->beacons += 1;
          auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
          if (pwr != 0)
            ap_info->pwr = pwr;
          break;
        }
      }
      if (exist == false) {
          // printf("새로운거 추가!\n");
          AirodumpApInfo ap_info(beacon_frame->bssid);
          ap_info.beacons = 1;
          auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
          if (pwr != 0)
            ap_info.pwr = pwr;
          ap_list.push_back(ap_info);
      }
    }
    else if (fc->type == Dot11FC::Type::DATA) {
      Dot11DataFrame* data_frame = (Dot11DataFrame*)fc;
      auto exist = false;
      for (auto ap_info = ap_list.begin(); ap_info != ap_list.end(); ++ap_info) {
        if (ap_info->bssid == data_frame->transmitter_addr) {
          exist = true;
          ap_info->num_data += 1;
          break;
        }
      }
      if (exist == false) {
          AirodumpApInfo ap_info(data_frame->transmitter_addr);
          ap_info.num_data = 1;
          auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
          if (pwr != 0)
            ap_info.pwr = pwr;
          ap_list.push_back(ap_info);
      }
    }

    clearConsole();
    printTableHeader();
    for (auto ap_info = ap_list.begin(); ap_info != ap_list.end(); ++ap_info) {
      std::cout << *ap_info << std::endl;
    }
  }

  pcap_close(handle);
  return 0;
}


// 암호화는 dot11 header에서 flag protected ==1 이고 ccmpㅣ면wpa
// WEP는 radiotap header의 flag에 항목이 있는 것 같다.
// RXQ는 sequence number를 봐서 비율을 따지면 되겠고.

