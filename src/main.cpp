#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

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
#include "my_radiotap.h" 
#include "Dot11.h"
#include "Dot11FrameBody.h"
#include "AirodumpApInfo.h"
#include "AirodumpStationInfo.h"
#include "RenderingThread.h"

#define DEBUG 0

using namespace wlan;


void usage(char *fname) {
  printf("syntax: %s <interface>\n", fname);
  printf("sample: %s mon0\n", fname);
}

std::map<MacAddr, AirodumpApInfo> ap_list;
std::map<MacAddr, AirodumpStationInfo> station_list;
std::atomic_flag container_lock = ATOMIC_FLAG_INIT;    // spin lock


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

#if !DEBUG
  RenderingThread _rendering_thread;
  std::thread rendering_thread( [&] { _rendering_thread.threadMain(
              ap_list, station_list, container_lock, dev); } );
#endif

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
#if DEBUG
    printf("%ld   : %u bytes captured\n", header->ts.tv_sec, header->caplen);
#endif

    while (container_lock.test_and_set());    // spin

    RadiotapHeader* radiotap = (RadiotapHeader*)packet;
    Dot11Frame* frame = (Dot11Frame*)(packet + radiotap->length);
    if (frame->getTypeSubtype() == Dot11FC::TypeSubtype::BEACON) {
      Dot11BeaconFrame* beacon_frame = (Dot11BeaconFrame*)frame;
      
      if (ap_list.count(beacon_frame->bssid)) {
        // already exist
        ap_list[beacon_frame->bssid].beacons += 1;
        auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
        if (pwr != 0)
          ap_list[beacon_frame->bssid].pwr = pwr;
      }
      else {
        // new AP
        AirodumpApInfo ap_info(beacon_frame->bssid);
        ap_info.beacons = 1;
        auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
        ap_info.pwr = (pwr != 0) ? pwr : ap_info.pwr;

        auto flags = *(int8_t*)radiotap->getField(PresentFlag::FLAGS);
        ap_info.preamble = (flags & PREAMBLE_MASK) ? '.' : ' ';

        Dot11FrameBody* frame_body = (Dot11FrameBody*)((uintptr_t)beacon_frame + sizeof(Dot11BeaconFrame));
        if (frame_body->capabilities_info & CAPABILITY_WEP) {
            ap_info.enc |= STD_WEP;
            ap_info.cipher |= ENC_WEP;
        }
        else {
            ap_info.enc |= STD_OPN;
        }

        // parse 802.11 Tagged Parameter
        uint8_t* it = (uint8_t*)((uintptr_t)beacon_frame + sizeof(Dot11BeaconFrame) + sizeof(Dot11FrameBody));
        ap_info.parseTaggedParam(it, packet + header->caplen);
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
        // new AP
        auto ds_status = data_frame->flags & 0b11;
        MacAddr bssid;
        MacAddr station;
        if (ds_status == 0b00) {
          // to ds from ds 둘 다 0일 때. receiver, transmitter 둘 다 station으로 추가해버림
          // src에서 dst로 direct하게 보내는거라 AP 정보는 없음. (not associated)   
          // airodump 예는 이럼. (not associated)   94:8B:C1:56:FC:E6  -38    0 - 1      0        2       
        }
        else if (ds_status == 0b01) {
          // to DS : 1
          bssid = data_frame->receiver_addr;
          station = data_frame->transmitter_addr;
        }
        else if (ds_status == 0b10) {
          // from DS : 1
          bssid = data_frame->transmitter_addr;
          station = data_frame->receiver_addr;
        }

        AirodumpApInfo ap_info(bssid);
        ap_info.num_data = 1;
        auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);
        if (pwr != 0)
          ap_info.pwr = pwr;
        
        // 채널 정보를 가져올 수 있는 TaggedParam이 없기 때문에 라디오탭 헤더에서 가져온다.
        auto channel_freq = *(int16_t*)radiotap->getField(PresentFlag::CHANNEL);
        if (channel_freq == 2484) {
          // channel 14만 frequency에서 공식으로 구할 수가 없다.
          ap_info.channel = 14;
        }
        else {
          ap_info.channel = (channel_freq - 2407) / 5;
        }

        // 여기서 길이 구해서 Dot11wlanElement를 호출해서 정보를 가져와야겠다. 그리고 ap_info에 넣어주기.
        ap_list[bssid] = ap_info;
        
        // station이 broadcast일 때는 station_list에는 추가하지 않는다.
        if (station != MacAddr::BROADCAST) {
          AirodumpStationInfo station_info(station);
          station_info.bssid = bssid;
          station_info.pwr = pwr;
          // station_info.rate
          // station_info.lost
          // station_info.frame
          station_list[station] = station_info;
        }
      }
    }

    container_lock.clear();
    
  }

  pcap_close(handle);
  return 0;
}

// RXQ는 sequence number를 봐서 비율을 따지면 되겠고.



