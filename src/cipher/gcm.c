#include "aes.h"
#include "mem.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define IV_LEN_BYTES 12
#define BLOCK_LEN_BYTES 16

typedef struct {
    uint64_t hi;
    uint64_t lo;
} U128;

static const U128 R = {
    .hi = 0xE100000000000000ULL,
    .lo = 0x0000000000000000ULL,
};

__attribute__((always_inline)) static inline U128
GcmMul(const U128 *const X, const U128 *const Y) {
    U128 Z = {0};
    U128 V = *Y;

    for (int i = 0; i < 128; ++i) {
        int Xi = i < 64 ? (X->hi >> (63 - i)) & 1 : (X->lo >> (127 - i)) & 1;

        if (Xi == 1) {
            Z.hi ^= V.hi;
            Z.lo ^= V.lo;
        }

        int lsb = V.lo & 1;

        uint64_t carry = V.hi & 1;
        V.hi >>= 1;
        V.lo = (V.lo >> 1) | (carry << 63);

        if (lsb == 1) {
            V.hi ^= R.hi;
            V.lo ^= R.lo;
        }
    }

    return Z;
}

__attribute__((always_inline)) static inline U128
GHASH(const U128 *const H, const U128 *const blocks, size_t n_blocks) {
    U128 Y = {0};

    for (size_t i = 0; i < n_blocks; ++i) {
        Y.hi ^= blocks[i].hi;
        Y.lo ^= blocks[i].lo;

        Y = GcmMul(&Y, H);
    }

    return Y;
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

bool
GCTR_test_empty_input_returns_empty_cipher() {
    uint8_t key[32] = {0};
    uint8_t plaintext[1] = {0};
    U128 ICB = {.hi = 0x0000000000000000ULL, .lo = 0x0100000000000000ULL};

    Aes256Data X = {0};
    AES256_Init(&X, key, plaintext, 0); // 0 length
    GCTR(&ICB, &X, &X);

    return X.msg.len == 0;
}

bool
GCTR_test_all_zero_input() {
    uint8_t key[32] = {0};
    uint8_t plaintext[16] = {0};
    U128 ICB = {.hi = 0, .lo = 0x0200000000000000}; // for little-endian, big endian would be 0x0000000000000002

    uint8_t expected[16] = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18};

    Aes256Data X = {0};
    AES256_Init(&X, key, plaintext, sizeof(plaintext));
    GCTR(&ICB, &X, &X);

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

    Aes256Data X = {0};
    AES256_Init(&X, key, plaintext, sizeof(plaintext));
    GCTR(&ICB, &X, &X);

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

    Aes256Data X = {0};
    AES256_Init(&X, key, plaintext, sizeof(plaintext));
    GCTR(&ICB, &X, &X);

    return ft_memcmp(X.msg.data, expected_ciphertext, 60) == 0;
}

bool
GHASH_test_empty_input_returns_zero() {
    U128 t1 = {0x66e94bd4ef8a2c3b, 0x884cfa59ca342b2e};
    U128 r1 = GHASH(&t1, NULL, 0);
    return r1.hi == 0 && r1.lo == 0;
}

bool
GHASH_test_two_blocks() {
    U128 t2 = {0x66e94bd4ef8a2c3b, 0x884cfa59ca342b2e};
    U128 blocks[2] = {
        (U128){.hi = 0x0388dace60b6a392, .lo = 0xf328c2b971b2fe78},
        (U128){.hi = 0x0000000000000000, .lo = 0x0000000000000080}
    };
    U128 r2 = GHASH(&t2, blocks, 2);
    return r2.hi == 0xf38cbb1ad69223dc && r2.lo == 0xc3457ae5b6b0f885;
}
