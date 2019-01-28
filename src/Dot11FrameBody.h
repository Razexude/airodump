#ifndef DOT11FRAMEBODY_H
#define DOT11FRAMEBODY_H

#include <cstdint>
#include <cstddef>
#include <utility>


namespace wlan {

const char MS_SPECIFIC_SECURITY[] = "\x00\x50\xf2\x01\x01\x00";
const char MS_SPECIFIC_QOS[] = "\x00\x50\xf2\x02\x01\x01";

const int  CAPABILITY_WEP = 0b10000;

namespace Dot11TagNum {
enum T {
	SSID		= 0,
	RATES		= 1,
	FHPARMS	= 2,
	DSPARMS	= 3,
	CFPARMS	= 4,
	TIM		= 5,
	IBSSPARMS	= 6,
	COUNTRY	= 7,
	EDCAPARMS	= 12,
	CHALLENGE	= 16,
	/* 17-31 reserved for challenge text extension */
	PWRCNSTR	= 32,
	PWRCAP		= 33,
	TPCREQ		= 34,
	TPCREP		= 35,
	SUPPCHAN	= 36,
	CHANSWITCHANN	= 37,
	MEASREQ	= 38,
	MEASREP	= 39,
	QUIET		= 40,
	IBSSDFS	= 41,
	ERP		= 42,
	HTCAP		= 45,	/* 11n */
	QOS_CAP	= 46,
	RSN		= 48,
	XRATES		= 50,
	TIE		= 56,	/* 11r */
	HTINFO		= 61,	/* 11n */
	MMIE		= 76,	/* 11w */
	TPC		= 150,
	CCKM		= 156,
	VENDOR		= 221	/* vendor private */
};
}
#pragma pack(push, 1)

typedef struct _Dot11FrameBody {
	uint64_t timestamp;      // fixed param
	uint16_t beacon_interval;
	uint16_t capabilities_info;

	std::pair<uint8_t*, uint8_t> getTaggedParam(Dot11TagNum::T tag, uint8_t* packet_end) {
        uint8_t* offset = (uint8_t*)this;
        offset += sizeof(struct _Dot11FrameBody);    // add fixed fields size
        while (*offset != tag && offset < packet_end) {
            offset += *(offset + 1);  // *(offset + 1) tag field length
            offset += 2;    // tag num field 1byte, tag len field 1byte
        }

        if (offset >= packet_end) {
			printf("NULL!!!\n");
            return std::pair<uint8_t*, uint8_t>(NULL, NULL);
        }

        return std::pair<uint8_t*, uint8_t>((offset + 2), *(offset + 1));  // tag data의 시작지점 offset과, length.
    };
} Dot11FrameBody;

#pragma pack(pop)

}
#endif