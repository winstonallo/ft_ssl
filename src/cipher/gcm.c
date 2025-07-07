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

// `Y->msg.data` is expected to have at least `X->msg.len` bytes allocated.
// `X->msg.data` and `Y->msg.data` may overlap.
__attribute__((always_inline)) static inline void
GCTR(const uint8_t *const restrict ICB, const Aes256Data *const X, Aes256Data *const Y) {
    if (X->msg.len == 0) {
        *Y = (Aes256Data){0};
        ft_memcpy(Y->key, X->key, sizeof(X->key));
        return;
    }

    const size_t n_complete_blocks = X->msg.len / BLOCK_LEN_BYTES;
    const size_t partial_block_len = X->msg.len % BLOCK_LEN_BYTES;
    uint8_t CB[16];
    ft_memcpy(CB, ICB, 16);
    // U128 CB = *ICB;

    for (size_t i = 0; i < n_complete_blocks; ++i) {
        uint8_t Ei[AES256_BLOCK_SIZE_BYTES];
        Cipher((uint8_t *)&CB, Ei, (uint32_t *)X->expanded_key);

        for (int j = 0; j < AES256_BLOCK_SIZE_BYTES; ++j) {
            Y->msg.data[(AES256_BLOCK_SIZE_BYTES * i) + j] = X->msg.data[(AES256_BLOCK_SIZE_BYTES * i) + j] ^ Ei[j];
        }

        if (i < n_complete_blocks - 1 || partial_block_len > 0) {
            uint32_t *counter_part = (uint32_t *)((uint8_t *)&CB + 12);
            *counter_part = BSWAP_32(BSWAP_32(*counter_part) + 1);
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

    uint8_t J0[16] = {0};
    ft_memcpy(J0, P->iv, 12);
    J0[15] |= 1;

    uint8_t J1[16] = {0};
    ft_memcpy(J1, J0, 16);

    uint32_t *counter_part = (uint32_t *)((uint8_t *)&J1[12]);
    *counter_part = BSWAP_32(BSWAP_32(*counter_part) + 1);

    GCTR(J1, (Aes256Data *)P, (Aes256Data *)P);

    const uint64_t msg_bits = P->msg.len * 8;
    const uint64_t aad_bits = P->aad.len * 8;
    const uint64_t u_bits = (128 - (msg_bits % 128)) % 128;
    const uint64_t v_bits = (128 - (aad_bits % 128)) % 128;
    const uint64_t u_bytes = u_bits / 8;
    const uint64_t v_bytes = v_bits / 8;

    printf("msg.len=%zu, aad.len=%zu\n", P->msg.len, P->aad.len);
    printf("msg_bits=%lu, aad_bits=%lu\n", msg_bits, aad_bits);
    printf("u_bits=%lu, v_bits=%lu\n", u_bits, v_bits);
    printf("u_bytes=%lu, v_bytes=%lu\n", u_bytes, v_bytes);

    const size_t S_buf_len = P->aad.len + v_bytes + P->msg.len + u_bytes + 16;
    uint8_t *const S_buf = ft_calloc(S_buf_len, 1);
    if (S_buf == NULL) {
        fprintf(stderr, "Error allocating S: %s\n", strerror(errno));
        return;
    }

    printf("S_buf_len=%zu\n", S_buf_len);

    const uint64_t aad_bitlen = BSWAP_64(P->aad.len * 8);
    const uint64_t msg_bitlen = BSWAP_64(P->msg.len * 8);

    size_t offset = 0;

    ft_memcpy(S_buf + offset, P->aad.data, P->aad.len);
    offset += P->aad.len + v_bytes;
    ft_memcpy(S_buf + offset, P->msg.data, P->msg.len);
    offset += P->msg.len + u_bytes;
    ft_memcpy(S_buf + offset, &aad_bitlen, 8);
    ft_memcpy(S_buf + offset + 8, &msg_bitlen, 8);

    printf("S_buf: ");
    for (size_t i = 0; i < S_buf_len; ++i) {
        printf("%02x", S_buf[i]);
    }
    printf("\n");

    uint8_t S[16] = {0};
    GHASH(H, S_buf, S_buf_len, S);

    uint8_t T_data_buf[16];
    ft_memcpy(T_data_buf, S, 16);

    Aes256Data T_data = {0};
    T_data.msg.data = T_data_buf;
    T_data.msg.len = 16;
    ft_memcpy(T_data.key, P->key, 32);
    ft_memcpy(T_data.expanded_key, P->expanded_key, 60 * sizeof(uint32_t));

    GCTR(J0, &T_data, &T_data);

    printf("H: ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", H[i]);
    }
    printf("\nJ0: ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", J0[i]);
    }
    printf("\nJ1: ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", J1[i]);
    }

    printf("\nS (GHASH result): ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", S[i]);
    }
    printf("\nAuthentication Tag: ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", T_data.msg.data[i]);
    }
    printf("\n");
}

bool
GCMAE_basic() {
    uint8_t key[32] = {0};
    uint8_t plaintext[1] = {0};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, 0); // 0 length
    uint8_t iv[12] = {0};
    ft_memcpy(X.iv, iv, 12);
    Aes256_GCM(&X, &X);
    return true;
}

bool
GCTR_test_empty_input_returns_empty_cipher() {
    uint8_t key[32] = {0};
    uint8_t plaintext[1] = {0};
    uint8_t ICB[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, 0); // 0 length
    GCTR(ICB, (Aes256Data *)&X, (Aes256Data *)&X);

    return X.msg.len == 0;
}

bool
GCTR_test_all_zero_input() {
    uint8_t key[32] = {0};
    uint8_t plaintext[16] = {0};
    uint8_t ICB[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

    uint8_t expected[16] = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, sizeof(plaintext));
    GCTR(ICB, (Aes256Data *)&X, (Aes256Data *)&X);

    return ft_memcmp(X.msg.data, expected, 16) == 0;
}

bool
GCTR_test_multiblock_no_remainder() {
    uint8_t key[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                       0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};

    uint8_t plaintext[64] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34,
                             0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24,
                             0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55};

    uint8_t ICB[16] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0x00, 0x00, 0x00, 0x02};

    uint8_t expected[64] = {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5,
                            0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10,
                            0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, sizeof(plaintext));
    GCTR(ICB, (Aes256Data *)&X, (Aes256Data *)&X);

    return ft_memcmp(X.msg.data, expected, 64) == 0;
}

bool
GCTR_test_multiblock_non_multiple_of_128() {
    uint8_t key[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                       0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};

    uint8_t plaintext[60] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
                             0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                             0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};

    uint8_t ICB[16] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0x00, 0x00, 0x00, 0x02};

    uint8_t expected_ciphertext[60] = {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc,
                                       0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
                                       0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62};

    Aes256Gcm X = {0};
    AES256_Init((Aes256Data *)&X, key, plaintext, sizeof(plaintext));
    GCTR(ICB, (Aes256Data *)&X, (Aes256Data *)&X);

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
    uint8_t t[16] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};
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
