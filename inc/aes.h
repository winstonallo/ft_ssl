#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES256_BLOCK_SIZE_BYTES 16
#define AES256_KEY_SIZE_BYTES 32
#define AES256_EXPANDED_KEY_SIZE_U32 (4 * (14 + 1))

typedef struct {
    struct {
        uint8_t *data;
        size_t len;
    } msg;
    uint8_t key[AES256_KEY_SIZE_BYTES];
    uint32_t expanded_key[AES256_EXPANDED_KEY_SIZE_U32];
} Aes256Data;

Aes256Data *Aes256_ECB_Encrypt(Aes256Data *);
Aes256Data *Aes256_ECB_Decrypt(Aes256Data *);

void AES256_Init(Aes256Data *data, const uint8_t key[AES256_KEY_SIZE_BYTES], const uint8_t *const msg, const size_t msg_len);
uint8_t *InvCipher(uint8_t *in, uint8_t *const out, uint32_t *w);
uint8_t *Cipher(const uint8_t *in, uint8_t *const out, uint32_t *w);
uint32_t *KeyExpansion(const uint8_t key[32], uint32_t *const out);

#endif
