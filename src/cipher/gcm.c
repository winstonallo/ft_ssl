#include "aes.h"
#include "alloc.h"
#include "bit.h"
#include "mem.h"
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IV_LEN_BYTES 12
#define BLOCK_LEN_BYTES 16

typedef struct {
    uint64_t hi;
    uint64_t lo;
} U128;

__attribute__((always_inline)) static inline void
GcmMul(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16]) {
    uint8_t Z[16] = {0};
    uint8_t V[16];

    ft_memcpy(V, Y, 16);

    // Process bits x0, x1, ..., x127 of X where x0 is leftmost bit
    for (int i = 0; i < 128; ++i) {
        // Get bit i from X (bit 0 is leftmost bit of byte 0)
        int bit = (X[i / 8] >> (7 - (i % 8))) & 1;

        if (bit == 1) {
            for (int j = 0; j < 16; ++j) {
                Z[j] ^= V[j];
            }
        }

        // Check LSB of V (rightmost bit)
        int lsb = V[15] & 1;

        // Right shift V by 1 bit
        for (int j = 15; j > 0; --j) {
            V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        }
        V[0] >>= 1;

        // If LSB was 1, XOR with R = 11100001 || 0^120
        if (lsb == 1) {
            V[0] ^= 0xe1;
        }
    }

    ft_memcpy(out, Z, 16);
}

__attribute__((always_inline)) static inline void
GHASH(const uint8_t H[16], const uint8_t *const data, size_t len, uint8_t out[16]) {
    uint8_t Y[16] = {0};

    for (size_t i = 0; i < len; i += 16) {
        uint8_t block[16] = {0};
        size_t block_len = (len - i) > 16 ? 16 : (len - i);

        // Copy the block (handles partial blocks correctly)
        ft_memcpy(block, data + i, block_len);

        // XOR with previous result
        for (int j = 0; j < 16; ++j) {
            Y[j] ^= block[j];
        }

        // Multiply by H
        GcmMul(Y, H, Y);
    }

    ft_memcpy(out, Y, 16);
}

__attribute__((always_inline)) static inline uint32_t
inc32_be(uint32_t num) {
    return __builtin_bswap32(__builtin_bswap32(num) + 1);
}

// `Y->msg.data` is expected to have at least `X->msg.len` bytes allocated.
// `X->msg.data` and `Y->msg.data` may overlap.
__attribute__((always_inline)) static inline void
GCTR(const U128 *const restrict ICB, const Aes256Data *const X, Aes256Data *const Y) {
    if (X->msg.len == 0) {
        *Y = (Aes256Data){0};
        ft_memcpy(Y->key, X->key, sizeof(X->key));
        return;
    }

    const size_t n_complete_blocks = X->msg.len / BLOCK_LEN_BYTES;
    const size_t partial_block_len = X->msg.len % BLOCK_LEN_BYTES;
    U128 CB = *ICB;

    for (size_t i = 0; i < n_complete_blocks; ++i) {
        uint8_t Ei[AES256_BLOCK_SIZE_BYTES];
        Cipher((uint8_t *)&CB, Ei, (uint32_t *)X->expanded_key);

        for (int j = 0; j < AES256_BLOCK_SIZE_BYTES; ++j) {
            Y->msg.data[(AES256_BLOCK_SIZE_BYTES * i) + j] = X->msg.data[(AES256_BLOCK_SIZE_BYTES * i) + j] ^ Ei[j];
        }

        if (i < n_complete_blocks - 1 || partial_block_len > 0) {
            uint32_t *counter_part = (uint32_t *)((uint8_t *)&CB + 12);
            *counter_part = inc32_be(*counter_part);
        }
    }

    if (partial_block_len > 0) {

        uint8_t Ei[AES256_BLOCK_SIZE_BYTES];
        Cipher((uint8_t *)&CB, Ei, (uint32_t *)X->expanded_key);

        for (size_t j = 0; j < partial_block_len; ++j) {
            Y->msg.data[(AES256_BLOCK_SIZE_BYTES * n_complete_blocks) + j] = X->msg.data[(AES256_BLOCK_SIZE_BYTES * n_complete_blocks) + j] ^ Ei[j];
        }
    }

    ft_memcpy(Y->key, X->key, sizeof(X->key));
    ft_memcpy(Y->expanded_key, X->expanded_key, sizeof(X->expanded_key));
    Y->msg.len = X->msg.len;
}

void
Aes256_GCM(Aes256Gcm *const P, Aes256Gcm *const out) {
    (void)out;

    uint8_t H[16] = {0};
    Cipher(H, H, P->expanded_key);

    U128 J0 = {0};
    J0.hi = BSWAP_64(*(uint64_t *)P->iv);
    J0.lo = ((uint64_t)BSWAP_32(*(uint32_t *)&P->iv[8]) << 32) | 0x1;

    U128 J1 = {J0.hi, J0.lo + 1};

    GCTR(&J1, (Aes256Data *)P, (Aes256Data *)P);

    const uint64_t u = (128 * ((P->msg.len * 8) / 128) - P->msg.len * 8);
    const uint64_t v = (128 * ((P->aad.len * 8) / 128) - P->aad.len * 8);

    uint8_t *const S = ft_calloc(P->aad.len + v + P->msg.len + u + 128, 1);
    if (S == NULL) {
        fprintf(stderr, "Error allocating S: %s\n", strerror(errno));
        return;
    }

    const uint64_t aad_bitlen = BSWAP_64(P->aad.len / 8);
    const uint64_t msg_bitlen = BSWAP_64(P->msg.len / 8);

    ft_memcpy(S, P->aad.data, P->aad.len);
    ft_memcpy(S + P->aad.len + v, P->msg.data, P->msg.len);
    ft_memcpy(S + P->aad.len + v + P->msg.len + u, &aad_bitlen, 8);
    ft_memcpy(S + P->aad.len + v + P->msg.len + u + 8, &msg_bitlen, 8);

    printf("0x%016lx%016lx\n", J1.hi, J1.lo);
}

bool
GCMAE_basic() {
    uint8_t key[32] = {0};
    uint8_t plaintext[1] = {0};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, 0); // 0 length
    uint8_t iv[12] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb};
    ft_memcpy(X.iv, iv, 12);
    Aes256_GCM(&X, &X);
    return true;
}

bool
GCTR_test_empty_input_returns_empty_cipher() {
    uint8_t key[32] = {0};
    uint8_t plaintext[1] = {0};
    U128 ICB = {.hi = 0x0000000000000000ULL, .lo = 0x0100000000000000ULL};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, 0); // 0 length
    GCTR(&ICB, (Aes256Data *)&X, (Aes256Data *)&X);

    return X.msg.len == 0;
}

bool
GCTR_test_all_zero_input() {
    uint8_t key[32] = {0};
    uint8_t plaintext[16] = {0};
    U128 ICB = {.hi = 0, .lo = 0x0200000000000000}; // for little-endian, big endian would be 0x0000000000000002

    uint8_t expected[16] = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, sizeof(plaintext));
    GCTR(&ICB, (Aes256Data *)&X, (Aes256Data *)&X);

    return ft_memcmp(X.msg.data, expected, 16) == 0;
}

bool
GCTR_test_multiblock_no_remainder() {
    uint8_t key[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                       0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};

    uint8_t plaintext[64] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34,
                             0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24,
                             0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55};

    U128 ICB = {.hi = 0xaddbcefabebafecaULL, .lo = 0x0200000088f8cadeULL};

    uint8_t expected[64] = {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5,
                            0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10,
                            0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, sizeof(plaintext));
    GCTR(&ICB, (Aes256Data *)&X, (Aes256Data *)&X);

    return ft_memcmp(X.msg.data, expected, 64) == 0;
}

bool
GCTR_test_multiblock_non_multiple_of_128() {
    uint8_t key[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                       0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};

    uint8_t plaintext[60] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
                             0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                             0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};

    U128 ICB = {.hi = 0xaddbcefabebafecaULL, .lo = 0x0200000088f8cadeULL};

    uint8_t expected_ciphertext[60] = {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc,
                                       0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
                                       0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, sizeof(plaintext));
    GCTR(&ICB, (Aes256Data *)&X, (Aes256Data *)&X);

    return ft_memcmp(X.msg.data, expected_ciphertext, 60) == 0;
}

bool
GHASH_test_empty_input_returns_zero() {
    uint8_t t[16] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x81, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};
    uint8_t out[16] = {0};
    GHASH(t, NULL, 0, out);

    for (int i = 0; i < 16; ++i) {
        if (out[i] != 0) {
            return false;
        }
    }
    return true;
}

bool
GHASH_test_two_blocks() {
    uint8_t t[16] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x81, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};
    uint8_t data[32] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80};
    uint8_t out[16] = {0};
    GHASH(t, data, sizeof(data), out);

    const uint8_t expected[16] = {0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0, 0xf8, 0x85};

    for (int i = 0; i < 16; ++i) {
        if (out[i] != expected[i]) {
            return false;
        }
    }
    return true;
}
