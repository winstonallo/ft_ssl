#include <sys/types.h>

// Rotates `val` to the left by `by` bits.
u_int32_t
rotl_32(u_int32_t val, const u_int32_t by) {
    return (val << by) | (val >> (32 - by));
}

// Rotates `val` to the right by `by` bits.
u_int32_t
rotr_32(u_int32_t val, const u_int32_t by) {
    return (val >> by) | (val << (32 - by));
}
