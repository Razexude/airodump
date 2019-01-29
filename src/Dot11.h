#ifndef DOT11_H
#define DOC11_H
#include <stdint.h>

#include "MacAddr.h"

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
		PROBE_REQUEST  = 0x04,
		PROBE_RESPONSE = 0x05,
		BEACON         = 0x08,
		BLOCK_ACK_REQ = 0x18,
		BLOCK_ACK     = 0x19,
		CLEAR_TO_SEND = 0x1c,
		ACK = 0x1d,
		DATA = 0x20,
		NULL_DATA = 0x24,
		QOS_DATA = 0x28
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