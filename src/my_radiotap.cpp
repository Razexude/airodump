
#include "my_radiotap.h"

#include <cstdint>

using namespace wlan;

static const struct _radiotap_size_info radiotap_size_arr[] = {
   [PresentFlag::TSFT]              = { .align = 8, .size = 8, },
   [PresentFlag::FLAGS]             = { .align = 1, .size = 1, },
   [PresentFlag::RATE]              = { .align = 1, .size = 1, },
   [PresentFlag::CHANNEL]           = { .align = 2, .size = 4, },
   [PresentFlag::FHSS]              = { .align = 2, .size = 2, },
   [PresentFlag::DBM_ANTSIGNAL]     = { .align = 1, .size = 1, },
   [PresentFlag::DBM_ANTNOISE]      = { .align = 1, .size = 1, },
   [PresentFlag::LOCK_QUALITY]      = { .align = 2, .size = 2, },
   [PresentFlag::TX_ATTENUATION]    = { .align = 2, .size = 2, },
   [PresentFlag::DB_TX_ATTENUATION] = { .align = 2, .size = 2, },
   [PresentFlag::DBM_TX_POWER]      = { .align = 1, .size = 1, },
   [PresentFlag::ANTENNA]           = { .align = 1, .size = 1, },
   [PresentFlag::DB_ANTSIGNAL]      = { .align = 1, .size = 1, },
   [PresentFlag::DB_ANTNOISE]       = { .align = 1, .size = 1, },
   [PresentFlag::RX_FLAGS]          = { .align = 2, .size = 2, },
   [PresentFlag::TX_FLAGS]          = { .align = 2, .size = 2, },
   [PresentFlag::RTS_RETRIES]       = { .align = 1, .size = 1, },
   [PresentFlag::DATA_RETRIES]      = { .align = 1, .size = 1, },
   [PresentFlag::CHANNEL_PLUS]      = { .align = 1, .size = 1, },
   [PresentFlag::MCS]               = { .align = 1, .size = 3, },
   [PresentFlag::AMPDU_STATUS]      = { .align = 4, .size = 8, },
   [PresentFlag::VHT]               = { .align = 2, .size = 12, },
   [PresentFlag::TIMESTAMP]         = { .align = 8, .size = 12, },
};


uint8_t* RadiotapHeader::getField(PresentFlag::T ps) {
    uintptr_t offset = (uintptr_t)this;

    // version, pad, length, present의 크기만큼 건너 뛰어준다.
    offset += sizeof(RadiotapHeader);

    // ext flag = 1인지 검사. 1이라면 Present flags word가 하나 더 있으므로 offset += 4
    if (present & (0b1 << 31)) {
        offset += 4;
    }

    // 반복문을 돌면서 인자로 받은 PresentFlag보다 앞에 있는 flag 중 1인 것들이 있으면,
    // 그 field가 있다는 의미이므로 그 field의 size만큼 offset에 더해줘서 건너뛴다.
    for (int i = 0; i < ps; i++) {
        if ((present >> i) & 0b1) {
            // alignment 해준다. 각 필드마다 요구하는 align 기준이 다르기 때문에 radiotap_size_arr에서 ps의 align을 읽어온다.
            if (offset % radiotap_size_arr[i].align != 0) {
                offset += radiotap_size_arr[i].align - (offset % radiotap_size_arr[i].align);
            }
            offset += radiotap_size_arr[i].size;
        }
    }

    

    // 아예 템플릿을 써서 여기서 값으로 바꿔서 내보낼까 하다가... 그냥 offset만 리턴하는걸로 처리.
    return (uint8_t*)offset;
}