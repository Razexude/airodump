#ifndef AIRODUMPLINE_H
#define AIRODUMPLINE_H

#include <string>

#include "MacAddr.h"


class AirodumpApInfo {
public:
  MacAddr bssid;
  int pwr;
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