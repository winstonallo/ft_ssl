#include "libft.h"
#include "ssl.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

#define MD5_BLOCK_SIZE 64 // 512 bits

typedef struct Message {
    union {
        char *bytes;
        uint16_t *words;
    } buf;

    size_t len;
} Message;

// Safety:
// `block` is assumed to be a buffer with a capacity of MD5_BLOCK_SIZE (512 bits,
// or 16 x 16 bit words).
void
md5_get_next_block(Message msg, size_t processed, uint16_t *block) {
    for (int idx = 0; idx < 16; ++idx) {
        block[idx] = msg.buf.words[idx + processed * 16];
    }
}

size_t
md5_calculate_padding(size_t original_size) {
    size_t padding_size = MD5_BLOCK_SIZE - (original_size % MD5_BLOCK_SIZE);

    if (padding_size < 9) {
        // If padding is less than 9 bytes, we append a whole block to leave room for
        // 0x80 and the length.
        padding_size += MD5_BLOCK_SIZE;
    }

    return padding_size;
}

Message
md5_pad(char *buf, size_t bit_len) {
    Message msg = {0};

    uint64_t buf_len = ft_strlen(buf);
    size_t padding_size = md5_calculate_padding(buf_len);

    buf = buf_realloc(buf, buf_len + padding_size);
    if (!buf) {
        perror("could not reallocate memory for buffer padding");
        return msg;
    }

    buf[buf_len] = (char)0x80;
    ft_memset(buf + buf_len + 1, 0, padding_size - 9);

    uint64_t original_bit_len = bit_len;
    ft_memcpy(buf + buf_len + padding_size - 8, &original_bit_len, 8);

    msg.buf.bytes = buf;
    msg.len = buf_len + padding_size;

    return msg;
}

char *
md5_hash(char *buf) {
    size_t bit_len = ft_strlen(buf) * 8;

    Message msg = md5_pad(buf, bit_len);

    for (size_t step = 0; step != msg.len; step += MD5_BLOCK_SIZE) {
        uint16_t block[16];

        md5_get_next_block(msg, step / MD5_BLOCK_SIZE, block);
        ft_printf("block %u: %s\n", step / MD5_BLOCK_SIZE, (char*)block);
    }

    free(msg.buf.bytes);
    return NULL;
}

int
md5(Options *const opts) {
    for (File *it = opts->targets; it; it = it->next) {
        md5_hash(it->content);
    }

    return 0;
}
