#ifndef DOT11_H
#define DOC11_H
#include <stdint.h>

#include "MacAddr.h"
#include "Dot11TaggedParam.h"

namespace wlan {

#pragma pack(push, 1)

typedef struct _Dot11Frame {
	uint8_t version: 2;
	uint8_t type: 2;
	uint8_t subtype: 4;
	uint8_t flags;
	uint16_t duration;
	MacAddr receiver_addr;

	inline uint8_t getTypeSubtype() {
		return (this->version << 6) + (this->type << 4) + this->subtype;
	}
} Dot11Frame;


typedef struct _Dot11MgtFrame: Dot11Frame {
	// receiver_addr == destination_addr 
	MacAddr transmitter_addr;   // == source addr == bssid
	MacAddr bssid;
	uint16_t frag_num: 4;
	uint16_t seq_num : 12;

} Dot11MgtFrame;

typedef struct _Dot11BeaconFrame: Dot11MgtFrame {
	// fixed parameter
	uint64_t timestamp;
	uint16_t beacon_interval;
	uint16_t capabilities_info;

	std::pair<uint8_t*, uint8_t> getTaggedParam(Dot11TagNum::T tag, uint8_t* packet_end) {
        uint8_t* offset = (uint8_t*)this;
        offset += sizeof(struct _Dot11BeaconFrame);    // add fixed fields size
        while (*offset != tag && offset < packet_end) {
            offset += *(offset + 1);  // *(offset + 1) tag field length
            offset += 2;    // tag num field 1byte, tag len field 1byte
        }

        if (offset >= packet_end) {
			// printf("NULL!!!\n");
            return std::pair<uint8_t*, uint8_t>(NULL, NULL);
        }

        return std::pair<uint8_t*, uint8_t>((offset + 2), *(offset + 1));  // tag data의 시작지점 offset과, length.
    };
} Dot11BeaconFrame;

typedef struct _Dot11AssoReqFrame: Dot11MgtFrame {
	uint16_t capabilities_info;
	uint16_t listen_interval;
} Dot11AssoReqFrame;

typedef struct _Dot11AssoResponFrame: Dot11MgtFrame {
	uint16_t capabilities_info;
	uint16_t status_code;
	uint16_t asso_id;
} Dot11AssoResponFrame;

typedef struct _Dot11ReAssoReqFrame: Dot11AssoReqFrame {
	MacAddr current_ap;
} Dot11ReAssoReqFrame;


typedef struct _Dot11DataFrame: Dot11Frame {
	// receiver_addr == destination_addr == sta_addr
	MacAddr transmitter_addr;  // == bssid
	MacAddr addr3;
	uint16_t frag_num: 4;
	uint16_t seq_num : 12;
} Dot11DataFrame;


#pragma pack(pop)
 
 
namespace Dot11FC {
	namespace Type {
	enum : uint8_t {
		MGT  = 0b00,
		CTRL = 0b01,
		DATA = 0b10
	};
	};

	namespace TypeSubtype {
	enum : uint8_t {
		ASSO_REQ       = 0x00,
		ASSO_RESPON    = 0x01,
		REASSO_REQ     = 0x02,
		REASSO_RESPON  = 0x03,
		PROBE_REQUEST  = 0x04,
		PROBE_RESPONSE = 0x05,
		BEACON         = 0x08,
		DEASSO  	   = 0x0a,
		AUTH           = 0x0b,
		DEAUTH   	   = 0x0c
	};
	};
};

namespace Dot11DS {
enum T {
	TO_FROM_DS = 0b00,
	TO_DS = 0b01,
	FROM_DS = 0b10
};
};

};
#endif