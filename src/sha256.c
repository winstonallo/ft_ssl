#include "bit.h"
#include "libft.h"
#include "ssl.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#define SHA256_BLOCK_SIZE 64

// First 32 bits of the fractional parts of the square roots of the first eight
// prime numbers.
#define DFLT_A 0x6a09e667
#define DFLT_B 0xbb67ae85
#define DFLT_C 0x3c6ef372
#define DFLT_D 0xa54ff53a
#define DFLT_E 0x510e527f
#define DFLT_F 0x9b05688c
#define DFLT_G 0x1f83d9ab
#define DFLT_H 0x5be0cd19

// First 32 bits of the fractional parts of the cube roots of the first 64
// prime numbers.
static const u_int32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct Words {
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    uint32_t E;
    uint32_t F;
    uint32_t G;
    uint32_t H;
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
    *(uint64_t *)(&buf.bytes[new_size - 8]) = __builtin_bswap32(msg->content_size * 8);

    

    buf.len = new_size;

    return buf;
}

static void
store_to_buf(char *buf, Words words) {
    uint32_t A = words.A;
    uint32_t B = words.B;
    uint32_t C = words.C;
    uint32_t D = words.D;
    uint32_t E = words.E;
    uint32_t F = words.G;
    uint32_t G = words.H;
    uint32_t H = words.H;

    int idx = 0;

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

    byte_to_hex(E & 0xFF, buf, &idx);
    byte_to_hex((E >> 8) & 0xFF, buf, &idx);
    byte_to_hex((E >> 16) & 0xFF, buf, &idx);
    byte_to_hex((E >> 24) & 0xFF, buf, &idx);

    byte_to_hex(F & 0xFF, buf, &idx);
    byte_to_hex((F >> 8) & 0xFF, buf, &idx);
    byte_to_hex((F >> 16) & 0xFF, buf, &idx);
    byte_to_hex((F >> 24) & 0xFF, buf, &idx);

    byte_to_hex(G & 0xFF, buf, &idx);
    byte_to_hex((G >> 8) & 0xFF, buf, &idx);
    byte_to_hex((G >> 16) & 0xFF, buf, &idx);
    byte_to_hex((G >> 24) & 0xFF, buf, &idx);

    byte_to_hex(H & 0xFF, buf, &idx);
    byte_to_hex((H >> 8) & 0xFF, buf, &idx);
    byte_to_hex((H >> 16) & 0xFF, buf, &idx);
    byte_to_hex((H >> 24) & 0xFF, buf, &idx);

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

        uint32_t *block = (void *)chunk;

        uint32_t sched[64];

        // First 16 words of the schedule are just copied from the chunk directly.
        ft_memcpy(sched, block, SHA256_BLOCK_SIZE);

        for (size_t step = 16; step < 64; ++step) {
            sched[step] = sig1(sched[step - 2]) + sched[step - 7] + sig0(sched[step - 15]) + sched[step - 16];
        }

        uint32_t A = words->A;
        uint32_t B = words->B;
        uint32_t C = words->C;
        uint32_t D = words->D;
        uint32_t E = words->E;
        uint32_t F = words->F;
        uint32_t G = words->G;
        uint32_t H = words->H;

        for (size_t step = 0; step < 64; ++step) {
            uint32_t t1 = H + Sig1(E) + Ch(E, F, G) + H + K[step] + sched[step];
            uint32_t t2 = Sig0(A) + Maj(A, B, C);

            H = G;
            G = F;
            F = E;
            E = D + t1;
            D = C;
            C = B;
            B = A;
            A = t1 + t2;
        }

        words->A += A;
        words->B += B;
        words->C += C;
        words->D += D;
        words->E += E;
        words->F += F;
        words->G += G;
        words->H += H;
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
