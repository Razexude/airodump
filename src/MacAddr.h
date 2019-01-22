#ifndef MAC_ADDR_H
#define MAC_ADDR_H

#include <cstdint>
#include <cstring>
#include <assert.h>

#pragma pack(push, 1)

class MacAddr final {
public:
    static const size_t LENGTH = 6;
private:
    uint8_t addr[LENGTH];

public:
    operator uint8_t*() { return addr; }
    void operator  =(const uint8_t* target) { memcpy(this->addr, target, LENGTH); }
    bool operator ==(const MacAddr& target) { return !memcmp(this->addr, target.addr, LENGTH); }
    bool operator ==(const uint8_t* target) { return !memcmp(this->addr, target, LENGTH); }
    bool operator !=(const MacAddr& target) { return memcmp(this->addr, target.addr, LENGTH); }
    bool operator !=(const uint8_t* target) { return memcmp(this->addr, target, LENGTH); }

    char* toString(char *str, size_t len) const;
    void print() const;
};

#pragma pack(pop)
#endif