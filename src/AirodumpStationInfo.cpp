
#include <cstdint>
#include <string>

#include "AirodumpStationInfo.h"
#include "Dot11TaggedParam.h"

using namespace wlan;

void AirodumpStationInfo::parseTaggedParam(uint8_t* it, const uint8_t* packet_end) {
    while (it < packet_end) {
        Dot11TaggedParam* t = (Dot11TaggedParam*)it; 

        if (t->num == Dot11TagNum::SSID && t->len != 0) {
            this->probe.insert(std::string(&(t->data), &(t->data) + t->len));
            // std::cout << "SSID : " << std::string(data, data + len) << std::endl;
        }

        it += 2 + t->len;    // tag num 1byte + tag len 1byte
    }
}

void AirodumpStationInfo::clearLost() {
    this->lost = 0;
}