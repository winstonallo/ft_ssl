#include <stdint.h>

// Fills `buf[*idx]` and `buf[*idx + 1]` with `byte`'s lowercase
// hexadecimal value.
// Safety:
// `buf[*idx]` and `buf[*idx + 1]` are assumed to be valid memory locations.
// Failure to ensure this will result in memory corruption.
void
byte_to_hex(uint8_t byte, char *buf, int *idx) {
    static const char digits[] = "0123456789abcdef";

    buf[*idx] = digits[(byte >> 4) & 0x0F];
    buf[*idx + 1] = digits[(byte) & 0x0F];
    *idx += 2;
}
