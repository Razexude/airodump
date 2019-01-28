#ifndef UMBUM_RADIOTAP_H
#define UMBUM_RADIOTAP_H

#include <cstdio>
#include <cstdint>

namespace wlan {

const uint8_t PREAMBLE_MASK = 0b10;

namespace PresentFlag {
enum T {
	TSFT = 0,
	FLAGS = 1,
	RATE = 2,
	CHANNEL = 3,
	FHSS = 4,
	DBM_ANTSIGNAL = 5,
	DBM_ANTNOISE = 6,
	LOCK_QUALITY = 7,
	TX_ATTENUATION = 8,
	DB_TX_ATTENUATION = 9,
	DBM_TX_POWER = 10,
	ANTENNA = 11,
	DB_ANTSIGNAL = 12,
	DB_ANTNOISE = 13,
	RX_FLAGS = 14,
	TX_FLAGS = 15,
	RTS_RETRIES = 16,
	DATA_RETRIES = 17,
	CHANNEL_PLUS = 18,
	MCS = 19,
	AMPDU_STATUS = 20,
	VHT = 21,
	TIMESTAMP = 22,

	/* valid in every it_present bitmap, even vendor namespaces */
	RADIOTAP_NAMESPACE = 29,
	VENDOR_NAMESPACE = 30,
	EXT = 31
};
}

struct _radiotap_size_info {
	uint8_t align;
	uint8_t size;
};


#pragma pack(push, 1)
typedef struct _RadiotapHeader {
public:
	uint8_t version;
	uint8_t pad;
	uint16_t length;
	uint32_t present;

public:
	// 여기서 template를 써야하나? 리턴값이 애매해지니까. auto는?? 쓰면 어떻게되나?
	uint8_t* getField(PresentFlag::T ps);
} RadiotapHeader;
#pragma pack(pop)

}
#endif



