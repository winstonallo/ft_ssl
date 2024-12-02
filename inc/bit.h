#ifndef BIT_H
#define BIT_H

#include <stdint.h>
#include <sys/types.h>

// rotate.c
uint32_t rotl_32(uint32_t val, const uint32_t by);
uint32_t rotr_32(uint32_t val, const uint32_t by);

#endif
