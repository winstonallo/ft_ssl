#include "alloc.h"
#include "bit.h"
#include "mem.h"
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
static const uint32_t K[] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                             0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                             0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                             0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                             0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

struct Words {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
} __attribute__((aligned(4)));

#define sig0(val) (ROTR_32(val, 7) ^ ROTR_32(val, 18) ^ val >> 3)
#define sig1(val) (ROTR_32(val, 17) ^ ROTR_32(val, 19) ^ val >> 10)

#define Sig0(val) (ROTR_32(val, 2) ^ ROTR_32(val, 13) ^ ROTR_32(val, 22))
#define Sig1(val) (ROTR_32(val, 6) ^ ROTR_32(val, 11) ^ ROTR_32(val, 25))

// `Ch` (choose/choice) selects bits from two input values `f` and `g` based on a selector `e`.
//
// For each bit `i`:
// - If the `i`-th bit of `e` is `1` (`e >> i & 1 == 1`), the corresponding bit in `ret` is taken from `f`.
// - Otherwise, the corresponding bit in `ret` is taken from `g`.
#define Ch(e, f, g) ((e & f) ^ (~e & g))

// `Maj` (majority) chooses each bit of the result `ret` based on the majority value
// of the corresponding bits in three input values `a`, `b`, and `c`.
//
// For each bit `i`:
// - If at least two of the three corresponding bits in `a`, `b`, and `c` are `1`, the `i`-th bit of `ret` will be `1`.
// - Otherwise, the `i`-th bit of `ret` will be `0`.
#define Maj(a, b, c) ((a & b) ^ (a & c) ^ (b & c))

// When padding the message, we append a single `1` bit to the message, followed by `k` `0` bits 
// where `k` is the minimum number `>= 0` such that `(L + 1 + k + 64) % 512 == 0` holds true.
// Finally, we append the original length of the message in bits as a big-endian 64-bit integer.
static Message
sha256_pad(File *msg) {
    Message buf = {0};

    uint64_t padding_size = SHA256_BLOCK_SIZE - ((msg->content_size % SHA256_BLOCK_SIZE) + 1) + ((msg->content_size % 64 > 55) ? 56 : (-8));

    uint64_t new_size = msg->content_size + padding_size + 1 + 8;

    if (new_size >= msg->allocated_bytes) {
        msg->set_reallocated;
        buf.bytes = ft_calloc(new_size, sizeof(char));
        if (!buf.bytes) {
            return buf;
        }
    } else {
        buf.bytes = (uint8_t *)msg->content;
    }

    ft_memcpy(buf.bytes, msg->content, msg->content_size);
    if (msg->reallocated && !(msg->option_s)) {
        free(msg->content);
    }

    buf.bytes[msg->content_size] = (uint8_t)0x80;

    uint64_t length_bits = (uint64_t)(msg->content_size * 8);

#if __BYTE_ORDER == __LITTLE_ENDIAN
    *(uint64_t *)(&buf.bytes[new_size - 8]) = BSWAP_64(length_bits);
#else
    *(uint64_t *)(&buf.bytes[new_size - 8]) = length_bits;
#endif

    buf.len = new_size;

    return buf;
}

static void
store_to_buf(char *buf, struct Words words) {
    uint32_t a = words.a;
    uint32_t b = words.b;
    uint32_t c = words.c;
    uint32_t d = words.d;
    uint32_t e = words.e;
    uint32_t f = words.f;
    uint32_t g = words.g;
    uint32_t h = words.h;

    int idx = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
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
#else
    byte_to_hex(a & 0xFF, buf, &idx);
    byte_to_hex((a >> 8) & 0xFF, buf, &idx);
    byte_to_hex((a >> 16) & 0xFF, buf, &idx);
    byte_to_hex((a >> 24) & 0xFF, buf, &idx);

    byte_to_hex(b & 0xFF, buf, &idx);
    byte_to_hex((b >> 8) & 0xFF, buf, &idx);
    byte_to_hex((b >> 16) & 0xFF, buf, &idx);
    byte_to_hex((b >> 24) & 0xFF, buf, &idx);

    byte_to_hex(c & 0xFF, buf, &idx);
    byte_to_hex((c >> 8) & 0xFF, buf, &idx);
    byte_to_hex((c >> 16) & 0xFF, buf, &idx);
    byte_to_hex((c >> 24) & 0xFF, buf, &idx);

    byte_to_hex(d & 0xFF, buf, &idx);
    byte_to_hex((d >> 8) & 0xFF, buf, &idx);
    byte_to_hex((d >> 16) & 0xFF, buf, &idx);
    byte_to_hex((d >> 24) & 0xFF, buf, &idx);

    byte_to_hex(e & 0xFF, buf, &idx);
    byte_to_hex((e >> 8) & 0xFF, buf, &idx);
    byte_to_hex((e >> 16) & 0xFF, buf, &idx);
    byte_to_hex((e >> 24) & 0xFF, buf, &idx);

    byte_to_hex(f & 0xFF, buf, &idx);
    byte_to_hex((f >> 8) & 0xFF, buf, &idx);
    byte_to_hex((f >> 16) & 0xFF, buf, &idx);
    byte_to_hex((f >> 24) & 0xFF, buf, &idx);

    byte_to_hex(g & 0xFF, buf, &idx);
    byte_to_hex((g >> 8) & 0xFF, buf, &idx);
    byte_to_hex((g >> 16) & 0xFF, buf, &idx);
    byte_to_hex((g >> 24) & 0xFF, buf, &idx);

    byte_to_hex(h & 0xFF, buf, &idx);
    byte_to_hex((h >> 8) & 0xFF, buf, &idx);
    byte_to_hex((h >> 16) & 0xFF, buf, &idx);
    byte_to_hex((h >> 24) & 0xFF, buf, &idx);
#endif

    buf[idx] = '\0';
}

static int
sha256_hash(File *msg, struct Words *words) {
    (void)words;

    Message buf = sha256_pad(msg);
    if (!buf.bytes) {
        return -1;
    }

    for (uint8_t *chunk = buf.bytes; (uint64_t)chunk - (uint64_t)buf.bytes < buf.len; chunk += SHA256_BLOCK_SIZE) {

        uint32_t W[64];

        // Here we build the message schedule (W). Each chunk (16 32-bit words) is extended to 64 32-bit words.
        // The first 16 words of the schedule are copied into the schedule.
#if __BYTE_ORDER == __LITTLE_ENDIAN
        W[0] = BSWAP_32(((uint32_t *)chunk)[0]);
        W[1] = BSWAP_32(((uint32_t *)chunk)[1]);
        W[2] = BSWAP_32(((uint32_t *)chunk)[2]);
        W[3] = BSWAP_32(((uint32_t *)chunk)[3]);
        W[4] = BSWAP_32(((uint32_t *)chunk)[4]);
        W[5] = BSWAP_32(((uint32_t *)chunk)[5]);
        W[6] = BSWAP_32(((uint32_t *)chunk)[6]);
        W[7] = BSWAP_32(((uint32_t *)chunk)[7]);
        W[8] = BSWAP_32(((uint32_t *)chunk)[8]);
        W[9] = BSWAP_32(((uint32_t *)chunk)[9]);
        W[10] = BSWAP_32(((uint32_t *)chunk)[10]);
        W[11] = BSWAP_32(((uint32_t *)chunk)[11]);
        W[12] = BSWAP_32(((uint32_t *)chunk)[12]);
        W[13] = BSWAP_32(((uint32_t *)chunk)[13]);
        W[14] = BSWAP_32(((uint32_t *)chunk)[14]);
        W[15] = BSWAP_32(((uint32_t *)chunk)[15]);
#else
        W[0] = ((uint32_t *)chunk)[0];
        W[1] = ((uint32_t *)chunk)[1];
        W[2] = ((uint32_t *)chunk)[2];
        W[3] = ((uint32_t *)chunk)[3];
        W[4] = ((uint32_t *)chunk)[4];
        W[5] = ((uint32_t *)chunk)[5];
        W[6] = ((uint32_t *)chunk)[6];
        W[7] = ((uint32_t *)chunk)[7];
        W[8] = ((uint32_t *)chunk)[8];
        W[9] = ((uint32_t *)chunk)[9];
        W[10] = ((uint32_t *)chunk)[10];
        W[11] = ((uint32_t *)chunk)[11];
        W[12] = ((uint32_t *)chunk)[12];
        W[13] = ((uint32_t *)chunk)[13];
        W[14] = ((uint32_t *)chunk)[14];
        W[15] = ((uint32_t *)chunk)[15];
#endif

        // The next 48 words are calculated with this formula:
        // `W(t) = 𝜎1(W(t - 2)) + W(t - 7) + 𝜎0(W(t - 15)) + W(t - 16)`,
        // where:
        // - t is the current iteration's index
        // - 𝜎0(x) = x >>> 7 ⊕ x >>> 18 ⊕ 7 >> 3
        // - 𝜎1(x) = x >>> 17 ⊕ x >>> 19 ⊕ x >> 10
        // Note that every addition is made % 2^32 - using any other type than u32 would result
        // in wrong calculations.
        W[16] = sig1(W[14]) + W[9] + sig0(W[1]) + W[0];
        W[17] = sig1(W[15]) + W[10] + sig0(W[2]) + W[1];
        W[18] = sig1(W[16]) + W[11] + sig0(W[3]) + W[2];
        W[19] = sig1(W[17]) + W[12] + sig0(W[4]) + W[3];
        W[20] = sig1(W[18]) + W[13] + sig0(W[5]) + W[4];
        W[21] = sig1(W[19]) + W[14] + sig0(W[6]) + W[5];
        W[22] = sig1(W[20]) + W[15] + sig0(W[7]) + W[6];
        W[23] = sig1(W[21]) + W[16] + sig0(W[8]) + W[7];
        W[24] = sig1(W[22]) + W[17] + sig0(W[9]) + W[8];
        W[25] = sig1(W[23]) + W[18] + sig0(W[10]) + W[9];
        W[26] = sig1(W[24]) + W[19] + sig0(W[11]) + W[10];
        W[27] = sig1(W[25]) + W[20] + sig0(W[12]) + W[11];
        W[28] = sig1(W[26]) + W[21] + sig0(W[13]) + W[12];
        W[29] = sig1(W[27]) + W[22] + sig0(W[14]) + W[13];
        W[30] = sig1(W[28]) + W[23] + sig0(W[15]) + W[14];
        W[31] = sig1(W[29]) + W[24] + sig0(W[16]) + W[15];
        W[32] = sig1(W[30]) + W[25] + sig0(W[17]) + W[16];
        W[33] = sig1(W[31]) + W[26] + sig0(W[18]) + W[17];
        W[34] = sig1(W[32]) + W[27] + sig0(W[19]) + W[18];
        W[35] = sig1(W[33]) + W[28] + sig0(W[20]) + W[19];
        W[36] = sig1(W[34]) + W[29] + sig0(W[21]) + W[20];
        W[37] = sig1(W[35]) + W[30] + sig0(W[22]) + W[21];
        W[38] = sig1(W[36]) + W[31] + sig0(W[23]) + W[22];
        W[39] = sig1(W[37]) + W[32] + sig0(W[24]) + W[23];
        W[40] = sig1(W[38]) + W[33] + sig0(W[25]) + W[24];
        W[41] = sig1(W[39]) + W[34] + sig0(W[26]) + W[25];
        W[42] = sig1(W[40]) + W[35] + sig0(W[27]) + W[26];
        W[43] = sig1(W[41]) + W[36] + sig0(W[28]) + W[27];
        W[44] = sig1(W[42]) + W[37] + sig0(W[29]) + W[28];
        W[45] = sig1(W[43]) + W[38] + sig0(W[30]) + W[29];
        W[46] = sig1(W[44]) + W[39] + sig0(W[31]) + W[30];
        W[47] = sig1(W[45]) + W[40] + sig0(W[32]) + W[31];
        W[48] = sig1(W[46]) + W[41] + sig0(W[33]) + W[32];
        W[49] = sig1(W[47]) + W[42] + sig0(W[34]) + W[33];
        W[50] = sig1(W[48]) + W[43] + sig0(W[35]) + W[34];
        W[51] = sig1(W[49]) + W[44] + sig0(W[36]) + W[35];
        W[52] = sig1(W[50]) + W[45] + sig0(W[37]) + W[36];
        W[53] = sig1(W[51]) + W[46] + sig0(W[38]) + W[37];
        W[54] = sig1(W[52]) + W[47] + sig0(W[39]) + W[38];
        W[55] = sig1(W[53]) + W[48] + sig0(W[40]) + W[39];
        W[56] = sig1(W[54]) + W[49] + sig0(W[41]) + W[40];
        W[57] = sig1(W[55]) + W[50] + sig0(W[42]) + W[41];
        W[58] = sig1(W[56]) + W[51] + sig0(W[43]) + W[42];
        W[59] = sig1(W[57]) + W[52] + sig0(W[44]) + W[43];
        W[60] = sig1(W[58]) + W[53] + sig0(W[45]) + W[44];
        W[61] = sig1(W[59]) + W[54] + sig0(W[46]) + W[45];
        W[62] = sig1(W[60]) + W[55] + sig0(W[47]) + W[46];
        W[63] = sig1(W[61]) + W[56] + sig0(W[48]) + W[47];

        uint32_t a = words->a;
        uint32_t b = words->b;
        uint32_t c = words->c;
        uint32_t d = words->d;
        uint32_t e = words->e;
        uint32_t f = words->f;
        uint32_t g = words->g;
        uint32_t h = words->h;

        // Once the message schedule is ready and we initialized our temporary variables a through h to
        // the current value of our worker variables, the compression step can begin.
        // We calculate 2 further temporary variables t1 and t2 with following formulas:
        //
        // t1(e, f, g, K) = h + Σ1(e) + Ch(e, f, g) + K(t) + W(t),
        // where:
        // - t is the current iteration's index (0..63)
        // - Σ1(x) = x >>> 6 ⊕ x >>> 11 ⊕ x >>> 25
        // - Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)
        //
        // t2(a, b, c) = Σ0(a) + Maj(a, b, c)
        // where:
        // - t is the current iteration's index (0..63)
        // - Σ0(x) = x >>> 2 ⊕ x >>> 13 ⊕ x >>> 22
        // - Maj(a, b, c) = (a ^ b) ⊕ (a ^ c) ⊕ (b ^ c)
        for (uint64_t t = 0; t < 64; ++t) {
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

    if (msg->reallocated) {
        free(buf.bytes);
    }

    return 0;
}

// `SHA2-256` is one of the most common hash functions, widely used in security applications/protocols,
// like TLS, SSL, SSH, or cryptocurrencies like BitCoin.
//
// https://en.wikipedia.org/wiki/SHA-2
int
sha256(File *msg, char *buf) {

    struct Words words = {DFLT_A, DFLT_B, DFLT_C, DFLT_D, DFLT_E, DFLT_F, DFLT_G, DFLT_H};
    sha256_hash(msg, &words);

    store_to_buf(buf, words);
    return 0;
}
