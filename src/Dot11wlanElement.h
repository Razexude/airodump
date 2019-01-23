#ifndef DOT11WLANELEMENT_H
#define DOT11WLANELEMENT_H

#include <cstdint>

namespace wlan {
#pragma pack(push, 1)

typedef struct _Dot11wlanElement {
	uint64_t timestamp;
	uint16_t beacon_interval;
	uint16_t capabilities_info;

public:
	uint8_t* getTagOffset(Dot11TagName::T tag, size_t max_len) {
		uintptr_t offset = 0;
		offset += sizeof(struct _Dot11wlanElement);
		if (offset < max_len) {
			
		}

		while (offset != tag) {
			offset += *(offset + 1);  // *(offset + 1) tag_len 
		}
		return offset;
	}
} Dot11wlanElement;



#pragma pack(pop)

namespace Dot11TagNum
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

#endif