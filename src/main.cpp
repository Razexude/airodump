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
#include "Dot11TaggedParam.h"
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
    // printf("%ld   : %u bytes captured\n", header->ts.tv_sec, header->caplen);

    RadiotapHeader* radiotap = (RadiotapHeader*)packet;
    Dot11Frame* frame = (Dot11Frame*)(packet + radiotap->length);
    if (frame->type == Dot11FC::Type::CTRL) {
      continue;    // not interested
    }
    auto pwr = *(int8_t*)radiotap->getField(PresentFlag::DBM_ANTSIGNAL);

    while (container_lock.test_and_set());    // spin

    if ((frame->getTypeSubtype() == Dot11FC::TypeSubtype::BEACON)
        || (frame->getTypeSubtype() == Dot11FC::TypeSubtype::PROBE_RESPONSE)) {
      // parse beacon or probe response
      Dot11BeaconFrame* beacon_frame = (Dot11BeaconFrame*)frame;
#if DEBUG
      std::cout << beacon_frame->bssid << std::endl;
#endif

      if (ap_list.count(beacon_frame->bssid) == 0) {
        // new AP
        AirodumpApInfo new_ap_info(beacon_frame->bssid);
        ap_list[beacon_frame->bssid] = new_ap_info;
      }

      AirodumpApInfo& ap_info = ap_list[beacon_frame->bssid];
      ap_info.beacons += 1;
      ap_info.pwr = (pwr != 0) ? pwr : ap_info.pwr;

      // parse Fixed Parameter
      if (beacon_frame->capabilities_info & CAPABILITY_WEP) {
        ap_info.enc |= STD_WEP;
        ap_info.cipher |= ENC_WEP;
      }
      else {
        ap_info.enc |= STD_OPN;
      }
      ap_info.preamble = (beacon_frame->capabilities_info & PREAMBLE_MASK) ? '.' : ' ';
      // parse 802.11 Tagged Parameter
      uint8_t* it = (uint8_t*)((uintptr_t)beacon_frame + sizeof(Dot11BeaconFrame));
      ap_info.parseTaggedParam(it, packet + header->caplen);

    }
    else if (frame->getTypeSubtype() == Dot11FC::TypeSubtype::PROBE_REQUEST) {
      // parse probe request. probe request는 station이 보낸다.
      Dot11MgtFrame* probe_req_frame = (Dot11MgtFrame*)frame;
      MacAddr station = probe_req_frame->transmitter_addr;
      // std::cout << station << " / " << probe_req_frame->bssid <<  std::endl;
      if (station_list.count(station) == 0) {
        // new station
        AirodumpStationInfo new_station_info(station);
        new_station_info.bssid = probe_req_frame->bssid;    // It's probably MacAddr::BROADCAST
        new_station_info.seq_num = probe_req_frame->seq_num;
        station_list[station] = new_station_info;
      }

      AirodumpStationInfo& station_info = station_list[station];
      // get ssid
      uint8_t* it = (uint8_t*)((uintptr_t)probe_req_frame + sizeof(Dot11MgtFrame));
      station_info.parseTaggedParam(it, packet + header->caplen);
      if (station_info.bssid == probe_req_frame->bssid) {
        int losts = probe_req_frame->seq_num - station_info.seq_num;
        if (losts > 0)
          station_info.lost += losts;
        station_info.seq_num = probe_req_frame->seq_num;
      }
      
      // airodump 설명에는 data 일 때만 증가시킨다고 되어 있는데, 실제로 실험해보면 probe request도 증가함.
      station_info.frames += 1;
      
    }
    else if (frame->type == Dot11FC::Type::DATA) {
      // parse data
      Dot11DataFrame* data_frame = (Dot11DataFrame*)frame;
      auto ds_status = data_frame->flags & 0b11;
      MacAddr bssid;
      MacAddr station;
      if (ds_status == Dot11DS::TO_FROM_DS) {
        // data 이면서 ds가 00인 패킷은 안잡히는 듯.
        goto while_end;
      }
      else if (ds_status == Dot11DS::TO_DS) {
        bssid = data_frame->receiver_addr;
        station = data_frame->transmitter_addr;
      }
      else if (ds_status == Dot11DS::FROM_DS) {
        bssid = data_frame->transmitter_addr;
        station = data_frame->receiver_addr;
      }

      if (ap_list.count(bssid) == 0) {
        // new AP
        AirodumpApInfo ap_info(bssid);
        
        // 채널 정보를 가져올 수 있는 TaggedParam이 없기 때문에 라디오탭 헤더에서 가져온다.
        int16_t channel_freq = *(int16_t*)radiotap->getField(PresentFlag::CHANNEL);
        if (channel_freq == 2484) {
          // channel 14만 frequency에서 공식으로 구할 수가 없다.
          ap_info.channel = 14;
        }
        else {
          ap_info.channel = (channel_freq - 2407) / 5;
        }
        ap_list[bssid] = ap_info;
      }
      ap_list[bssid].num_data += 1;
      if (pwr != 0)
        ap_list[bssid].pwr = pwr;

      // station이 broadcast일 때는 station_list에는 추가하지 않는다.
      if (station != MacAddr::BROADCAST) {
        if (station_list.count(station) == 0) {
          // new station
          AirodumpStationInfo new_station_info(station);
          station_list[station] = new_station_info;
        }
        AirodumpStationInfo& station_info = station_list[station];

        if (pwr != 0)
          station_info.pwr = pwr;

        if (station_info.bssid != bssid) {
          station_info.bssid = bssid;
          station_info.seq_num = 0;
          station_info.lost = 0;
        }

        // update losts : to ds 일 때만 seq_num을 갱신.
        if (ds_status == Dot11DS::TO_DS) {
          if (station_info.seq_num != 0) {
            int losts = data_frame->seq_num - station_info.seq_num;
            if (losts > 0)
              station_info.lost += losts;
          }
          station_info.seq_num = data_frame->seq_num;
        }

        // set rate & qos
        if (ds_status == Dot11DS::TO_DS) {
          station_info.st_to_ap_rate = *(radiotap->getField(PresentFlag::RATE)) / 2;
          station_info.st_to_ap_qos  = (data_frame->subtype & 0b1000) ? 'e' : ' ';
        }
        else if (ds_status == Dot11DS::FROM_DS) {
          station_info.ap_to_st_rate = *(radiotap->getField(PresentFlag::RATE)) / 2;
          station_info.ap_to_st_qos  = (data_frame->subtype & 0b1000) ? 'e' : ' ';
        }
        
        station_info.frames += 1;
      }
      
    }

while_end:
    container_lock.clear();
    
  }

  pcap_close(handle);
  return 0;
}

// RXQ는 sequence number를 봐서 비율을 따지면 되겠고.



