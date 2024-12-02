#include "bit.h"
#include "libft.h"
#include "ssl.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#define SHA256_BLOCK_SIZE 64

// First 32 bits of the fractional parts of the square roots of the first eight
// prime numbers.
#define DFLT_A 0x6a09e667UL
#define DFLT_B 0xbb67ae85UL
#define DFLT_C 0x3c6ef372UL
#define DFLT_D 0xa54ff53aUL
#define DFLT_E 0x510e527fUL
#define DFLT_F 0x9b05688cUL
#define DFLT_G 0x1f83d9abUL
#define DFLT_H 0x5be0cd19UL

// First 32 bits of the fractional parts of the cube roots of the first 64
// prime numbers.
static const uint32_t K[] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2};

typedef struct Words {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
} Words;

static uint32_t
sig0(uint32_t val) {
    return rotr_32(val, 7) ^ rotr_32(val, 18) ^ val >> 3;
}

static uint32_t
sig1(uint32_t val) {
    return rotr_32(val, 17) ^ rotr_32(val, 19) ^ val >> 10;
}

static uint32_t
Sig0(uint32_t val) {
    return rotr_32(val, 2) ^ rotr_32(val, 13) ^ rotr_32(val, 22);
}

static uint32_t
Sig1(uint32_t val) {
    return rotr_32(val, 6) ^ rotr_32(val, 11) ^ rotr_32(val, 25);
}

static uint32_t
Ch(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

static uint32_t
Maj(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

size_t
calculate_padding(size_t original_size) {
    if (original_size % 64 > 55) {
        return SHA256_BLOCK_SIZE - ((original_size % SHA256_BLOCK_SIZE) + 1) + 56;
    } else {
        return SHA256_BLOCK_SIZE - ((original_size % SHA256_BLOCK_SIZE) + 1) - 8;
    }
}

Message
sha256_pad(File *msg) {
    Message buf = {0};

    uint64_t padding_size = calculate_padding(msg->content_size);

    ssize_t new_size = msg->content_size + padding_size + 1 + 8;

    if (new_size >= msg->allocated_bytes) {
        msg->reallocated = true;
        buf.bytes = malloc(new_size * sizeof(char));
        if (!buf.bytes) {
            return buf;
        }
    } else {
        buf.bytes = (uint8_t *)msg->content;
    }

    ft_memcpy(buf.bytes, msg->content, msg->content_size);
    if (msg->reallocated) {
        free(msg->content);
    }

    buf.bytes[msg->content_size] = (char)0x80;
    *(uint64_t *)(&buf.bytes[new_size - 8]) = (uint64_t)__builtin_bswap64(msg->content_size * 8);
    buf.len = new_size;

    return buf;
}

static void
store_to_buf(char *buf, Words words) {
    uint32_t a = words.a;
    uint32_t b = words.b;
    uint32_t c = words.c;
    uint32_t d = words.d;
    uint32_t e = words.e;
    uint32_t f = words.f;
    uint32_t g = words.g;
    uint32_t h = words.h;

    int idx = 0;

    byte_to_hex((a >> 24) & 0xFF, buf, &idx);
    byte_to_hex((a >> 16) & 0xFF, buf, &idx);
    byte_to_hex((a >> 8) & 0xFF, buf, &idx);
    byte_to_hex(a & 0xFF, buf, &idx);

    byte_to_hex((b >> 24) & 0xFF, buf, &idx);
    byte_to_hex((b >> 16) & 0xFF, buf, &idx);
    byte_to_hex((b >> 8) & 0xFF, buf, &idx);
    byte_to_hex(b & 0xFF, buf, &idx);

    byte_to_hex((c >> 24) & 0xFF, buf, &idx);
    byte_to_hex((c >> 16) & 0xFF, buf, &idx);
    byte_to_hex((c >> 8) & 0xFF, buf, &idx);
    byte_to_hex(c & 0xFF, buf, &idx);

    byte_to_hex((d >> 24) & 0xFF, buf, &idx);
    byte_to_hex((d >> 16) & 0xFF, buf, &idx);
    byte_to_hex((d >> 8) & 0xFF, buf, &idx);
    byte_to_hex(d & 0xFF, buf, &idx);

    byte_to_hex((e >> 24) & 0xFF, buf, &idx);
    byte_to_hex((e >> 16) & 0xFF, buf, &idx);
    byte_to_hex((e >> 8) & 0xFF, buf, &idx);
    byte_to_hex(e & 0xFF, buf, &idx);

    byte_to_hex((f >> 24) & 0xFF, buf, &idx);
    byte_to_hex((f >> 16) & 0xFF, buf, &idx);
    byte_to_hex((f >> 8) & 0xFF, buf, &idx);
    byte_to_hex(f & 0xFF, buf, &idx);

    byte_to_hex((g >> 24) & 0xFF, buf, &idx);
    byte_to_hex((g >> 16) & 0xFF, buf, &idx);
    byte_to_hex((g >> 8) & 0xFF, buf, &idx);
    byte_to_hex(g & 0xFF, buf, &idx);

    byte_to_hex((h >> 24) & 0xFF, buf, &idx);
    byte_to_hex((h >> 16) & 0xFF, buf, &idx);
    byte_to_hex((h >> 8) & 0xFF, buf, &idx);
    byte_to_hex(h & 0xFF, buf, &idx);

    buf[idx] = '\0';
}

static int
sha256_hash(File *msg, Words *words) {
    (void)words;

    Message buf = sha256_pad(msg);
    if (!buf.bytes) {
        return -1;
    }

    for (uint8_t *chunk = buf.bytes; (size_t)chunk - (size_t)buf.bytes < buf.len; chunk += SHA256_BLOCK_SIZE) {

        uint32_t W[64];

        for (size_t t = 0; t < 16; ++t) {
            W[t] = __builtin_bswap32(((uint32_t *)chunk)[t]);
        }

        for (size_t t = 16; t < 64; ++t) {
            W[t] = sig1(W[t - 2]) + W[t - 7] + sig0(W[t - 15]) + W[t - 16];
        }

        uint32_t a = words->a;
        uint32_t b = words->b;
        uint32_t c = words->c;
        uint32_t d = words->d;
        uint32_t e = words->e;
        uint32_t f = words->f;
        uint32_t g = words->g;
        uint32_t h = words->h;

        for (size_t t = 0; t < 64; ++t) {
            uint32_t t1 = h + Sig1(e) + Ch(e, f, g) + K[t] + W[t];
            uint32_t t2 = Sig0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        words->a += a;
        words->b += b;
        words->c += c;
        words->d += d;
        words->e += e;
        words->f += f;
        words->g += g;
        words->h += h;
    }
    free(buf.bytes);
    return 0;
}

int
sha256(File *msg, char *buf) {

    Words words = {DFLT_A, DFLT_B, DFLT_C, DFLT_D, DFLT_E, DFLT_F, DFLT_G, DFLT_H};
    sha256_hash(msg, &words);

    store_to_buf(buf, words);
    return 0;
}
