#ifndef UMBUM_RADIOTAP_H
#define UMBUM_RADIOTAP_H

#include <cstdint>

namespace wlan{
#pragma pack(push, 1)


struct _PresentFlags {
	uint32_t tsft : 1,
	uint32_t flags : 1,
	uint32_t rate : 1,
	uint32_t channel : 1,
	uint32_t fhss : 1,
	uint32_t dbm_antsignal : 1,
	uint32_t dbm_antnoise : 1,
	uint32_t lock_quality : 1,
	uint32_t tx_attenuation : 1,
	uint32_t db_tx_attenuation : 1,
	uint32_t dbm_tx_power : 1,
	uint32_t antenna : 1,
	uint32_t db_antsignal : 1,
	uint32_t db_antnoise : 1,
	uint32_t rx_flags : 1,
	uint32_t tx_flags : 1,
	uint32_t rts_retries : 1,
	uint32_t data_retries : 1,
	uint32_t channel_plus : 1,
	uint32_t mcs : 1,
	uint32_t ampdu_status : 1,
	uint32_t vht : 1,
	uint32_t timestamp : 1,
    uint32_t he : 1,
    uint32_t he_mu : 1,
    uint32_t reserved : 4,
    uint32_t radiotap_ns_next : 1,
    uint32_t vendor_ns_next : 1,
    uint32_t ext : 1
};


typedef struct _RadiotapHeader {
	uint8_t version;
	uint8_t pad;
	uint16_t length;
	struct _PresentFlags present;

	uint16_t getChannel() {
		/***
		 * 더 우아하게 처리하려면?
		 * 리스트에 ext의 size, align 정보 넣고, 함수의 인자로 몇 번째 정보인지를 받음.
		 * 몇 번째 정보인지가 곧 index이니까, 이 index까지 반복돌면서 리스트에서 size꺼내서 offset에 더해감.
		 * 이런 식으로 처리하면 하드코딩 안해도 된다.
		 */
		uint8_t* offset = 0;
		uint8_t* align  = 0;
		if (!present.channel) {
			return NULL;
		}

		if (present.ext)
			offset += 4;

		if (present.tsft)
			offset += 8;
		
		if (present.flags)
			offset += 1;
		
		if (present.rate)
			offset += 1;
		else
			align += 1;
		
		uint8_t *p_channel_frequency = ((uint8_t*)this + offset + align);
		return ntohs(p_channel_frequency);
	}
} RadiotapHeader;


#pragma pack(pop)
}

#endif
