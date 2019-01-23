

#include "Dot11wlanElement.h"

namespace wlan {

static const size_t wlan_element_size_arr[] = {
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

}
