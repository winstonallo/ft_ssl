#ifndef SSL_H
#define SSL_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define STRCMP(a, b) (ft_strncmp(a, b, ft_strlen(a)))

typedef struct File {
    const char *path;
    uint8_t *content;
    size_t content_size;
    bool allocated;
    size_t allocated_bytes;
    bool reallocated;
    bool option_s;
    struct File *next;
} File;

typedef struct Message {
    uint8_t *bytes;
    size_t len;
} Message;

typedef struct Options {
    bool p;
    bool q;
    bool r;
    bool h;
    File *targets;
} Options;

typedef enum Command {
    CMD_INVALID = -1,
    CMD_MD5 = 0,
    CMD_SHA256 = 1,
    CMD_HELP = 2,
} Command;

// md5.c
int md5(File *msg, char *buf);

// sha256.c
int sha256(File *msg, char *buf);

// help.c
int help();

// options.c
Command options_parse(struct Options *const args, char **argv);
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
