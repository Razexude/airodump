#ifndef AIRODUMPSTATIONINFO_H
#define AIRODUMPSTATIONINFO_H

#include <set>
#include <chrono>

#include "MacAddr.h"

using namespace std::chrono;

class AirodumpStationInfo {
public:
    MacAddr      bssid;
    MacAddr      station;
    int          pwr  = 0;
    unsigned int ap_to_st_rate = 0;
    unsigned int st_to_ap_rate = 0;
    char         ap_to_st_qos  = ' ';
    char         st_to_ap_qos  = ' ';
    unsigned int lost = 0;
    unsigned int frames = 0;
    unsigned int seq_num = 0;
    std::set<std::string>  probe;
    system_clock::time_point clear_time = system_clock::now();
    
    AirodumpStationInfo() {}
    AirodumpStationInfo(MacAddr _station): station(_station) {}

    void clearLost();
    void parseTaggedParam(uint8_t* it, const uint8_t* packet_end);

    friend std::ostream& operator<<(std::ostream& os, AirodumpStationInfo& obj) {
        std::string bssid = (obj.bssid == MacAddr::BROADCAST) ? "(not associated) " : (std::string)obj.bssid;
        std::string probe_str;
        for (auto it = obj.probe.begin(); it != obj.probe.end(); it++) {
            probe_str += *it + ',';
        }
        return os << " " << bssid
                    << "  " << obj.station
                    << std::setw(5) << obj.pwr << "   " 
                    << std::setw(2) << obj.ap_to_st_rate << obj.ap_to_st_qos << "-" << obj.st_to_ap_rate << obj.st_to_ap_qos
                    << std::setw(7) << obj.lost << " "
                    << std::setw(8) << obj.frames << "  "
                    << probe_str;
    }

};

#endif