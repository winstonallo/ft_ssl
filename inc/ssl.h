#ifndef SSL_H
#define SSL_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct File {
    const char *path;
    uint8_t *content;
    uint64_t content_size;
    uint64_t allocated_bytes;
    struct File *next;

    // Bitset for storing flags, saves 24 bytes, enabling the struct
    // to fit on a single cache line.
    uint8_t flags;

#define allocated flags & 0x01
#define set_allocated flags |= 0x01

#define option_s flags & 0x02
#define set_option_s flags |= 0x02

#define reallocated flags & 0x04
#define set_reallocated flags |= 0x04

#define failed flags & 0x08
#define set_failed flags |= 0x08

} File;

typedef struct Algo {
    int (*f)(File *, char *);
    char *cmd;
    char *display_name;
    uint8_t output_buffer_size;
} Algo;

typedef struct Message {
    uint8_t *bytes;
    uint64_t len;
} Message;

extern const Algo algo_map[];

typedef struct Options {
    bool p;
    bool q;
    bool r;
    File *targets;
} Options;

// md5.c
int md5(File *msg, char *buf);

// sha256.c
int sha256(File *msg, char *buf);

// help.c
int help();

// options.c
Algo *options_parse(struct Options *const args, char **av);
void options_cleanup(File *head);

// alloc.c
u_int8_t *buf_realloc(u_int8_t *old_buf, ssize_t new_size, ssize_t old_size);

// file.c
int file_read_all(Options *const opts);

// hex.c
void byte_to_hex(u_int8_t byte, char *buf, int *idx);

// display.c
void display(char *hash, char *algo_name, File *file, const struct Options *const opts);

#endif
