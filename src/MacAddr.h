#ifndef MAC_ADDR_H
#define MAC_ADDR_H

#include <iostream>
#include <cstdint>
#include <cstring>
#include <iomanip>


#pragma pack(push, 1)

class MacAddr final {
public:
    static const size_t LENGTH = 6;
private:
    uint8_t addr[LENGTH];

public:
    MacAddr() {}
    MacAddr(uint8_t *target) { memcpy(this->addr, target, LENGTH); }

    operator uint8_t*() { return addr; }
    void operator=(const uint8_t* target) { memcpy(this->addr, target, LENGTH); }
    bool operator==(const MacAddr& target) { return !memcmp(this->addr, target.addr, LENGTH); }
    bool operator==(const uint8_t* target) { return !memcmp(this->addr, target, LENGTH); }
    bool operator!=(const MacAddr& target) { return memcmp(this->addr, target.addr, LENGTH); }
    bool operator!=(const uint8_t* target) { return memcmp(this->addr, target, LENGTH); }

    operator std::string() const { 
        char buf[18];
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        return std::string(buf);
    }
    friend std::ostream& operator<<(std::ostream& os, MacAddr& obj) { 
        return os << std::hex << std::setfill('0') <<
                        std::setw(2) << unsigned(obj.addr[0]) << ":" <<
                        std::setw(2) << unsigned(obj.addr[1]) << ":" <<
                        std::setw(2) << +obj.addr[2] << ":" <<
                        std::setw(2) << unsigned(obj.addr[3]) << ":" <<
                        std::setw(2) << unsigned(obj.addr[4]) << ":" <<
                        std::setw(2) << unsigned(obj.addr[5]) <<
                    std::dec << std::setfill(' '); 
    }

};

#pragma pack(pop)
#endif