#ifndef DOT11_H
#define DOC11_H
#include <stdint.h>

#include "packet.h"

namespace wlan {

#pragma pack(push, 1)

typedef struct _RadiotapHeader {
	uint8_t version;
	uint8_t pad;
	uint16_t length;
	uint32_t present_flag1;
	uint32_t present_flag2;
	uint8_t flags;
	uint8_t data_rate;
	uint16_t channel_frequency;
} RadiotapHeader;


struct _Dot11FrameControl {
	union {
		struct {
			uint8_t version: 2;
			uint8_t type: 2;
			uint8_t subtype: 4;
		};
		uint8_t type_subtype;
	};
	uint8_t flags;
};

typedef struct _Dot11Frame {
	struct _Dot11FrameControl fc;
	uint16_t duration;
	uint8_t receiver_addr[packet::Len::MAC_ADDR];
} Dot11Frame;

typedef struct _Dot11DataFrame: Dot11Frame {
	// receiver_addr == destination_addr == sta_addr
	uint8_t transmitter_addr[packet::Len::MAC_ADDR];  // == bssid
	uint8_t source_addr[packet::Len::MAC_ADDR];
	uint16_t frag_number: 4;
	uint16_t seq_number : 12;
	uint64_t ccmp_params;
} Dot11DataFrame;

typedef struct _Dot11QoSDataFrame: Dot11Frame {
	// receiver_addr == destination_addr == sta_addr
	uint8_t transmitter_addr[packet::Len::MAC_ADDR];    // == bssid
	uint8_t source_addr[packet::Len::MAC_ADDR];
	uint16_t frag_number: 4;
	uint16_t seq_number : 12;
	uint16_t qos_ctrl;
	uint64_t ccmp_params;
} Dot11QoSFrame;

typedef struct _Dot11BeaconFrame: Dot11Frame {
	// receiver_addr == destination_addr 
	uint8_t transmitter_addr[packet::Len::MAC_ADDR];    // == source_addr
	uint8_t bssid[packet::Len::MAC_ADDR];
} Dot11BeaconFrame;


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
		BEACON = 0x08,
		BLOCK_ACK_REQ = 0x18,
		ACK = 0x1d,
		DATA = 0x20,
		NULL_DATA = 0x24,
		QOS_DATA = 0x28
	};
	};
};
};
#endif