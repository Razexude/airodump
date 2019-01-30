#ifndef DOT11TAGGEDPARAM_H
#define DOT11TAGGEDPARAM_H

#include <cstdint>
#include <cstddef>
#include <utility>
#include <string>


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


typedef struct _Dot11TaggedParam {
	uint8_t num;
	uint8_t len;
	uint8_t data;

	uint8_t getChannel() { return data; }
	uint8_t getSpeed() {
		uint8_t speed = *(&data + len - 1); // 현재 Tag의 마지막 데이터
		return (speed & 0x7F) / 2;
	}
	std::string getSsid() { return std::string(&data, &data + len); }


	// TODO : operator overloading해서 iter처럼 쓰면 좋겠다.
	// 상속을 받자니 offset이 틀어질거같고. 어쩐다? std::vector<int>::iterator 이거 따라가보면, 어쨌든 iterator도 내부에 current 변수가 있어야 하긴 함.
	// struct _TaggedParam& operator++() {
		
	// 	this += 2 + this->len;
	// 	return *this;
	// }
	// struct _TaggedParam  operator++(int) {

	// 	T temp = *this ;
	// 	return temp ;
	// }
} Dot11TaggedParam;

#pragma pack(pop)

}
#endif