
#include <cstdint>
#include <string>

#include "AirodumpStationInfo.h"
#include "Dot11FrameBody.h"

using namespace wlan;

void AirodumpStationInfo::parseTaggedParam(uint8_t* it, const uint8_t* packet_end) {
    while (it < packet_end) {
        auto tag = it[0];
        auto len = it[1];
        auto data = it + 2;

        if (tag == Dot11TagNum::SSID && len != 0) {
            this->probe.insert(std::string(data, data + len));
            // std::cout << "SSID : " << std::string(data, data + len) << std::endl;
        }

        it += 2 + len;    // tag num 1byte + tag len 1byte
    }
}

void AirodumpStationInfo::clearLost() {
    this->lost = 0;
}