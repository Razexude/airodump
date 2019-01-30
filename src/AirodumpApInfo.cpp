
#include "AirodumpApInfo.h"
#include "Dot11TaggedParam.h"

using namespace wlan;


void AirodumpApInfo::parseTaggedParam(uint8_t* it, const uint8_t* packet_end) {   
    // TODO : iterator로 변경할 수 있을 듯. it을 구조체로 변경하면서 ++를 오버로딩하면 될 듯? 
    // 그리고 어떤Tag에 대한 파싱을 각각의 구조체가 아니라, 구조체는 TaggedParam 공통 하나만 만들고 한 Tag당 하나의 parser메서드를 만들어서 이를 호출하는 형태로 하면 좋을듯. 그러려면 &ap_info를 인자로 받아야겠군.
    while (it < packet_end)  {
        // it[0] = Tag num    it[1] = Tag len    it[2~] = Tag data
        Dot11TaggedParam* t = (Dot11TaggedParam*)it; 
        auto tag = t->num;
        auto len = t->len;
        auto data = &(t->data);
        
        
        if (tag == Dot11TagNum::DSPARMS) {
            this->channel = t->getChannel();
        }
        else if (tag == Dot11TagNum::RATES || tag == Dot11TagNum::XRATES) {
            auto speed = t->getSpeed();
            this->max_speed = (this->max_speed < speed) ? speed : this->max_speed;
        }
        else if (tag == Dot11TagNum::SSID) {
            this->essid = t->getSsid();
        }
        else if (tag == Dot11TagNum::VENDOR &&
            (len >= 8) && (memcmp(data, MS_SPECIFIC_QOS, 6) == 0)) {
            this->qos = 'e';
        }
        else if (tag == Dot11TagNum::VENDOR &&
            (len >= 8) && (memcmp(data, MS_SPECIFIC_SECURITY, 6) == 0)) {
            this->enc &= ~(STD_WEP | STD_WPA);
            this->cipher &= ~(ENC_WEP);

            this->enc |= STD_WPA;
        }
        else if (tag == Dot11TagNum::RSN) {
            this->enc &= ~(STD_WEP | STD_WPA);
            this->cipher &= ~(ENC_WEP);

            this->enc |= STD_WPA2;
            auto pairwise_suite_cnt = data[6] + (data[7] << 8);  // ver 2B + Group suite 4B
            auto pairwise_idx = 6 + 2;
            for (auto i = 0; i < pairwise_suite_cnt; i++) {
                switch (data[pairwise_idx + (i*4) + 3]) {    // + 3은 type 위치
                    case 0x01:
                        this->cipher |= ENC_WEP;
                        break;
                    case 0x02:
                        this->cipher |= ENC_TKIP;
                        break;
                    case 0x03:
                        this->cipher |= ENC_WRAP;
                        break;
                    case 0x0A:
                    case 0x04:
                        this->cipher |= ENC_CCMP;
                        break;
                    case 0x05:
                        this->cipher |= ENC_WEP104;
                        break;
                    case 0x08:
                    case 0x09:
                        this->cipher |= ENC_GCMP;
                        break;
                    default:
                        break;
                }
            }

            auto akm_suite_cnt = data[pairwise_idx + (pairwise_suite_cnt*4)] + (data[pairwise_idx + (pairwise_suite_cnt*4) + 1] << 8);
            auto akm_idx = pairwise_idx + (pairwise_suite_cnt*4) + 2;
            for (auto i = 0; i < akm_suite_cnt; i++) {
                switch (data[akm_idx + (i*4) + 3]) {    // + 3은 type 위치
                    case 0x01:
                        this->auth |= AUTH_MGT;
                        break;
                    case 0x02:
                        this->auth |= AUTH_PSK;
                        break;
                    default:
                        break;
                }
            }
        }

        it += 2 + len;    // tag num 1byte + tag len 1byte
    }
}

void AirodumpApInfo::updateDataPerSec() {
    this->num_data_per_sec = this->num_data - this->last_num_data;
    this->last_num_data = this->num_data;
}