#include <stdio.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>

#include <map>
#include <vector>
#include <string>
#include <thread>
#include <atomic>

#include "MacAddr.h"
#include "dot11.h"
#include "util.h"
#include "my_radiotap.h"
#include "AirodumpApInfo.h"
#include "RenderingThread.h"

using namespace wlan;


void usage(char *fname) {
  printf("syntax: %s <interface>\n", fname);
  printf("sample: %s mon0\n", fname);
}

// TODO : lock 걸어야지?
std::map<MacAddr, AirodumpApInfo> ap_list;
// std::map<MacAddr, AirodumpStationInfo> station_list;
std::atomic_flag ap_list_lock = ATOMIC_FLAG_INIT;    // spin lock

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

  RenderingThread _rendering_thread;
  std::thread rendering_thread( [&] { _rendering_thread.threadMain(ap_list, ap_list_lock); } );

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    // printf("%ld   : %u bytes captured\n", header->ts.tv_sec, header->caplen);

    while (ap_list_lock.test_and_set());

    RadiotapHeader* radiotap = (RadiotapHeader*)packet;
    // printf("radiotap length [%hu]\n", radiotap->length);
    Dot11Frame* frame = (Dot11Frame*)(packet + radiotap->length);
    if (frame->getTypeSubtype() == Dot11FC::TypeSubtype::BEACON) {
      Dot11BeaconFrame* beacon_frame = (Dot11BeaconFrame*)frame;
      // std::cout << beacon_frame->bssid << std::endl;
      // printf("type[%x]channel[%x]\n",
      //                           frame->getTypeSubtype(), 
      //                           *(int16_t*)radiotap->getField(PresentFlag::CHANNEL));
      
      if (ap_list.count(beacon_frame->bssid)) {
        // already exist
        ap_list[beacon_frame->bssid].beacons += 1;
        auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
        if (pwr != 0)
          ap_list[beacon_frame->bssid].pwr = pwr;
      }
      else {
        // printf("새로운거 추가!\n");
        AirodumpApInfo ap_info(beacon_frame->bssid);
        ap_info.beacons = 1;
        auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
        if (pwr != 0)
          ap_info.pwr = pwr;
        // 여기서 길이 구해서 Dot11wlanElement를 호출해서 정보를 가져와야겠다. 그리고 ap_info에 넣어주기.
        ap_list[beacon_frame->bssid] = ap_info;
      }
    }
    else if (frame->type == Dot11FC::Type::DATA) {
      Dot11DataFrame* data_frame = (Dot11DataFrame*)frame;
      if (ap_list.count(data_frame->transmitter_addr)) {
        // already exist
        ap_list[data_frame->transmitter_addr].num_data += 1;
        auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
        if (pwr != 0)
          ap_list[data_frame->transmitter_addr].pwr = pwr;
      }
      else {
        // printf("새로운거 추가!\n");
        AirodumpApInfo ap_info(data_frame->transmitter_addr);
        ap_info.num_data = 1;
        auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
        if (pwr != 0)
          ap_info.pwr = pwr;
        // 여기서 길이 구해서 Dot11wlanElement를 호출해서 정보를 가져와야겠다. 그리고 ap_info에 넣어주기.
        ap_list[data_frame->transmitter_addr] = ap_info;
      }
    }

    ap_list_lock.clear();
    
  }

  pcap_close(handle);
  return 0;
}


// 암호화는 dot11 header에서 flag protected ==1 이고 ccmpㅣ면wpa
// WEP는 radiotap header의 flag에 항목이 있는 것 같다.
// RXQ는 sequence number를 봐서 비율을 따지면 되겠고.

