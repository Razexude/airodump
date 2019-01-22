#ifndef AIRODUMPLINE_H
#define AIRODUMPLINE_H

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
};

#endif