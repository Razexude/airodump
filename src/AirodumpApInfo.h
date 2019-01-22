#ifndef AIRODUMPLINE_H
#define AIRODUMPLINE_H

#include <iomanip>

#include <cstdint>
#include <string>

#include "MacAddr.h"


class AirodumpApInfo {
public:
  MacAddr bssid;
  int8_t pwr;
  unsigned int beacons = 0;
  unsigned int num_data = 0;
  unsigned int num_data_per_sec = 0;
  unsigned int channel;
  std::string maximum_speed;
  std::string enc;
  std::string cipher;
  std::string auth;
  std::string essid;

public:
  AirodumpApInfo(MacAddr _bssid): bssid(_bssid) {}

  friend std::ostream& operator<<(std::ostream& os, AirodumpApInfo& obj) {
    return os << " " << obj.bssid << 
                 std::setw(5) << int(obj.pwr) << " " << 
                 std::setw(8) << obj.beacons << " " << 
                 std::setw(8) << obj.num_data << " " <<
                 std::setw(4) << obj.num_data_per_sec << " ";
                //  obj.channel << " " <<
                //  obj.maximum_speed << " " <<
                //  obj.enc << " " <<
                //  obj.cipher << " " <<
                //  obj.auth << " " <<
                //  obj.essid;
    }

};

#endif