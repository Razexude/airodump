#ifndef MAC_ADDR_H
#define MAC_ADDR_H

#include <stdint.h>
#include <stdio.h>
#include <assert.h>


#pragma pack(push, 1)

class MacAddr final {
public:
    static const size_t LENGTH = 6;
private:
    uint8_t addr[LENGTH];

public:
    char* toString(char *str, size_t len) const;
    void print() const;
};
#pragma pack(pop)

#endif