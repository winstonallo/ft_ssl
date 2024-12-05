#include "bit.h"
#include "libft.h"
#include "ssl.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define MD5_BLOCK_SIZE 64 // 512 bits

// Rotates `x` to the left by `n` bits

#define DFLT_A 0x67452301
#define DFLT_B 0xefcdab89
#define DFLT_C 0x98badcfe
#define DFLT_D 0x10325476

// The values for K are derived from following formula:
// `abs(sin(i + 1)) * pow(2, 32)`
//
// The indices used are defined by the current MD5 round:
// - Round 1: `K[0..15]`
// - Round 2: `K[16..31]`
// - Round 3: `K[32..47]`
// - Round 4: `K[48..63]`
static const uint32_t K[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static const uint32_t s[] = {7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
                             14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
                             4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21};

static const uint8_t block_idx[] = {0,  1,  2,  3,  4, 5, 6,  7, 8,  9,  10, 11, 12, 13, 14, 15, 1, 6,  11, 0, 5, 10,
                                    15, 4,  9,  14, 3, 8, 13, 2, 7,  12, 5,  8,  11, 14, 1,  4,  7, 10, 13, 0, 3, 6,
                                    9,  12, 15, 2,  0, 7, 14, 5, 12, 3,  10, 1,  8,  15, 6,  13, 4, 11, 2,  9};

typedef struct Words {
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
} Words;

// When padding the message, we append a single `1` bit to the message, followed by `k` `0` bits such
// that where `k` is the minimum number `>= 0` such that `(L + 1 + k + 64) % 512 == 0` holds true.
// Finally, we append the original length of the message in bits as a big-endian 64-bit integer.
static Message
md5_pad(File *msg) {
    Message buf = {0};

    uint64_t padding_size = MD5_BLOCK_SIZE - ((msg->content_size % MD5_BLOCK_SIZE) + 1) + ((msg->content_size % 64 > 55) ? 56 : (-8));

    size_t new_size = msg->content_size + padding_size + 1 + 8;

    if (new_size >= msg->allocated_bytes) {
        msg->reallocated = true;
        buf.bytes = ft_calloc(new_size, sizeof(char));
        if (!buf.bytes) {
            return buf;
        }
    } else {
        buf.bytes = (uint8_t *)msg->content;
    }

    ft_memcpy(buf.bytes, msg->content, msg->content_size);
    if (msg->reallocated && !msg->option_s) {
        free(msg->content);
    }

    buf.bytes[msg->content_size] = (char)0x80;

#if __BYTE_ORDER == __LITTLE_ENDIAN
    *(uint64_t *)(&buf.bytes[new_size - 8]) = msg->content_size * 8;
#else 
    *(uint64_t *)(&buf.bytes[new_size - 8]) = __builtin_bswap64(msg->content_size * 8);
#endif


    buf.len = new_size;

    return buf;
}

static void
md5_store_to_buf(char *buf, Words words) {
    uint32_t A = words.A;
    uint32_t B = words.B;
    uint32_t C = words.C;
    uint32_t D = words.D;

    int idx = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
    byte_to_hex(A & 0xFF, buf, &idx);
    byte_to_hex((A >> 8) & 0xFF, buf, &idx);
    byte_to_hex((A >> 16) & 0xFF, buf, &idx);
    byte_to_hex((A >> 24) & 0xFF, buf, &idx);

    byte_to_hex(B & 0xFF, buf, &idx);
    byte_to_hex((B >> 8) & 0xFF, buf, &idx);
    byte_to_hex((B >> 16) & 0xFF, buf, &idx);
    byte_to_hex((B >> 24) & 0xFF, buf, &idx);

    byte_to_hex(C & 0xFF, buf, &idx);
    byte_to_hex((C >> 8) & 0xFF, buf, &idx);
    byte_to_hex((C >> 16) & 0xFF, buf, &idx);
    byte_to_hex((C >> 24) & 0xFF, buf, &idx);

    byte_to_hex(D & 0xFF, buf, &idx);
    byte_to_hex((D >> 8) & 0xFF, buf, &idx);
    byte_to_hex((D >> 16) & 0xFF, buf, &idx);
    byte_to_hex((D >> 24) & 0xFF, buf, &idx);
#else 
    byte_to_hex((A >> 24) & 0xFF, buf, &idx);
    byte_to_hex((A >> 16) & 0xFF, buf, &idx);
    byte_to_hex((A >> 8) & 0xFF, buf, &idx);
    byte_to_hex(A & 0xFF, buf, &idx);

    byte_to_hex((B >> 24) & 0xFF, buf, &idx);
    byte_to_hex((B >> 16) & 0xFF, buf, &idx);
    byte_to_hex((B >> 8) & 0xFF, buf, &idx);
    byte_to_hex(B & 0xFF, buf, &idx);

    byte_to_hex((C >> 24) & 0xFF, buf, &idx);
    byte_to_hex((C >> 16) & 0xFF, buf, &idx);
    byte_to_hex((C >> 8) & 0xFF, buf, &idx);
    byte_to_hex(C & 0xFF, buf, &idx);

    byte_to_hex((D >> 24) & 0xFF, buf, &idx);
    byte_to_hex((D >> 16) & 0xFF, buf, &idx);
    byte_to_hex((D >> 8) & 0xFF, buf, &idx);
    byte_to_hex(D & 0xFF, buf, &idx);
#endif

    buf[idx] = '\0';
}

static int
md5_hash(File *msg, Words *words) {

    Message buf = md5_pad(msg);
    if (!buf.bytes) {
        return -1;
    }

    for (uint8_t *chunk = buf.bytes; (size_t)chunk - (size_t)buf.bytes < buf.len; chunk += MD5_BLOCK_SIZE) {

        uint32_t *block = (void *)chunk;

        uint32_t A = words->A;
        uint32_t B = words->B;
        uint32_t C = words->C;
        uint32_t D = words->D;

        for (size_t step = 0; step < 64; ++step) {
            uint32_t F;
            uint32_t g;

            if (step < 16) {
                F = (B & C) | ((~B) & D);
            } else if (step < 32) {
                F = (D & B) | ((~D) & C);
            } else if (step < 48) {
                F = B ^ C ^ D;
            } else {
                F = C ^ (B | (~D));
            }

            g = block_idx[step];

            F += A + K[step] + block[g];
            A = D;
            D = C;
            C = B;
            B += rotl_32(F, s[step]);
        }

        words->A += A;
        words->B += B;
        words->C += C;
        words->D += D;
    }

    if (msg->reallocated) {
        free(buf.bytes);
    }

    return 0;
}

// Memory Safety:
// `buf` is assumed to be a buffer capable of holding `33 bytes` (the size of
// the MD5 hash function's output + `\0`). Failure to ensure this will lead to
// memory corruption.
// Cryptographic Safety:
// - The MD5 hash algorithm is not collision-resistant. This should not
// be used for anything else than educational purposes.
// https://en.wikipedia.org/wiki/MD5
int
md5(File *msg, char *buf) {
    Words words = {DFLT_A, DFLT_B, DFLT_C, DFLT_D};

    if (md5_hash(msg, &words) == -1) {
        return -1;
    }

    md5_store_to_buf(buf, words);
    return 0;
}
