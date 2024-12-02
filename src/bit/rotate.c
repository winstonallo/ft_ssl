#include <stdint.h>
#include <sys/types.h>

// Rotates `val` to the left by `by` bits.
uint32_t
rotl_32(uint32_t val, uint32_t by) {
    if ((by &= 32 - 1) == 0) {
        return val;
    }
    return (val << by) | (val >> (32 - by));
}

// Rotates `val` to the right by `by` bits.
uint32_t
rotr_32(uint32_t val, uint32_t by) {
    if ((by &= 32 - 1) == 0) {
        return val;
    }
    return (val >> by) | (val << (32 - by));
}
