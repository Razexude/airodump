#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

void printPacket(uint8_t *p, int len);

void parse_ip(const uint8_t*);
void parse_tcp(const uint8_t*, uint16_t);
#endif