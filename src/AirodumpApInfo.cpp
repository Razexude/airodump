
#include "AirodumpApInfo.h"
#include "Dot11FrameBody.h"

using namespace wlan;

void AirodumpApInfo::parseTaggedParam(uint8_t* it, const uint8_t* packet_end) {   
    // TODO : iterator로 변경할 수 있을 듯. it을 구조체로 변경하면서 ++를 오버로딩하면 될 듯? 근데 지금처럼 가도 별 문제 없을 것 같은데. 가독성도 괜찮고.
    while (it < packet_end)  {
        // it[0] = Tag num    it[1] = Tag len    it[2~] = Tag data
        auto tag = it[0];
        auto len = it[1];
        auto data = it + 2;    
        switch (tag) {
            case Dot11TagNum::DSPARMS:
                this->channel = *data;
                break;
            case Dot11TagNum::RATES:
            case Dot11TagNum::XRATES:
            {
                auto _speed = *(data + len - 1); // 현재 Tag의 마지막 데이터
                auto speed = (_speed & 0x7F) / 2;
                this->max_speed = (this->max_speed < speed) ? speed : this->max_speed;
                break;
            }
            case Dot11TagNum::VENDOR:
                if ((len >= 8) && (memcmp(data, MS_SPECIFIC_QOS, 6) == 0)) {
                    this->qos = '.';
                    break;
                }
                if ((len >= 8) || (memcmp(data, MS_SPECIFIC_SECURITY, 6) == 0)) {
                    this->enc |= STD_WPA;
                    break;
                }
                break;
            case Dot11TagNum::RSN:
                this->enc |= STD_WPA2;
                break;
            case Dot11TagNum::SSID:
                this->essid = std::string(data, data + len);
                break;
        }
        it += 2 + len;    // tag num 1byte + tag len 1byte
    }
}