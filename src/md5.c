#include "libft.h"
#include "ssl.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DFLT_A 0x67452301
#define DFLT_B 0xefcdab89
#define DFLT_C 0x98badcfe
#define DFLT_D 0x10325476

#define MD5_BLOCK_SIZE 64 // 512 bits

// Rotates `x` to the left by `n` bits
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

typedef struct Words {
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
} Words;

typedef struct Message {
    union {
        uint8_t *bytes;
        uint32_t *words;
    } buf;

    size_t len;
} Message;

// The values for K are derived from following formula:
// `abs(sin(i + 1)) x pow(2, 32)`
// The indices used are defined by the current md5 round:
// Round 1: K[0..15]
// Round 2: K[16..31]
// Round 3: K[32..47]
// Round 4: K[48..63]
static const uint32_t K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1,
                             0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
                             0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942,
                             0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                             0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
                             0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static const uint32_t s[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// Safety:
// `block` is assumed to be a buffer with a capacity of MD5_BLOCK_SIZE (512 bits,
// or 16 x 32 bit words).
void
md5_get_next_block(Message msg, size_t processed, uint32_t *block) {
    for (int idx = 0; idx < 16; ++idx) {
        block[idx] = msg.buf.words[idx + processed * 16];
        printf("%08x\n", block[idx]);
    }
}

size_t
md5_calculate_padding(size_t original_size) {
    size_t padding_size;

    if (original_size % 64 > 55) {
        padding_size = MD5_BLOCK_SIZE - ((original_size % MD5_BLOCK_SIZE) + 1) + 56;
    } else {
        padding_size = MD5_BLOCK_SIZE - ((original_size % MD5_BLOCK_SIZE) + 1) - 8;
    }

    return padding_size;
}

Message
md5_pad(char *buf) {
    Message msg = {0};

    uint64_t buf_len = ft_strlen(buf);
    size_t padding_size = md5_calculate_padding(buf_len);
    printf("padding size: %zu\n", padding_size);

    size_t new_size = buf_len + padding_size + 1 + 8;

    msg.buf.bytes = malloc(sizeof(char) * new_size);
    if (!msg.buf.bytes) {
        return msg;
    }

    ft_memcpy(msg.buf.bytes, buf, buf_len);
    msg.buf.bytes[buf_len] = (char)0x80;
    ft_memset(msg.buf.bytes + buf_len + 1, 0, padding_size);
    *(size_t *)(&buf[new_size - 8]) = buf_len * 8;

    msg.len = new_size;

    return msg;
}

typedef uint32_t (*MD5_Round)(uint32_t, uint32_t, uint32_t);

void
md5_print(uint32_t A, uint32_t B, uint32_t C, uint32_t D, const char *filename) {
    printf("MD5(%s)= ", filename);
    printf("%02x%02x%02x%02x", A & 0xFF, (A >> 8) & 0xFF, (A >> 16) & 0xFF, (A >> 24) & 0xFF);
    printf("%02x%02x%02x%02x", B & 0xFF, (B >> 8) & 0xFF, (B >> 16) & 0xFF, (B >> 24) & 0xFF);
    printf("%02x%02x%02x%02x", C & 0xFF, (C >> 8) & 0xFF, (C >> 16) & 0xFF, (C >> 24) & 0xFF);
    printf("%02x%02x%02x%02x", D & 0xFF, (D >> 8) & 0xFF, (D >> 16) & 0xFF, (D >> 24) & 0xFF);
    printf("\n");
}

Words
md5_hash(char *buf, Words words) {
    Message msg = md5_pad(buf);

    uint32_t a0 = DFLT_A;
    uint32_t b0 = DFLT_B;
    uint32_t c0 = DFLT_C;
    uint32_t d0 = DFLT_D;

    for (unsigned char *chunk = msg.buf.bytes; (size_t)chunk - (size_t)msg.buf.bytes < msg.len; chunk += MD5_BLOCK_SIZE) {

        uint32_t *block = (void *)chunk;
        uint32_t A = a0;
        uint32_t B = b0;
        uint32_t C = c0;
        uint32_t D = d0;

        for (size_t step = 0; step < 64; ++step) {
            uint32_t F;
            uint32_t g;

            if (step < 16) {
                F = (B & C) | ((~B) & D);
                g = step;
            } else if (step < 32) {
                F = (D & B) | ((~D) & C);
                g = (5 * step + 1) % 16;
            } else if (step < 48) {
                F = B ^ C ^ D;
                g = (3 * step + 5) % 16;
            } else {
                F = C ^ (B | (~D));
                g = (7 * step) % 16;
            }

            F = F + A + K[step] + block[g];
            A = D;
            D = C;
            C = B;
            B += ROTL(F, s[step]);
        }

        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;
    }

    words.A = a0;
    words.B = b0;
    words.C = c0;
    words.D = d0;

    free(msg.buf.bytes);
    return words;
}

int
md5(Options *const opts) {
    for (File *it = opts->targets; it; it = it->next) {
        Words words = {DFLT_A, DFLT_B, DFLT_C, DFLT_D};

        Words hashed_words = md5_hash(it->content, words);

        md5_print(hashed_words.A, hashed_words.B, hashed_words.C, hashed_words.D, it->path);
    }

    return 0;
}
