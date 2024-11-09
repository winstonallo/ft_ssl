#ifndef SSL_H
#define SSL_H

#include <stdbool.h>
#include <time.h>

typedef struct File {
    const char *path;
    struct File *next;
} File;

typedef struct Options {
    bool p;
    bool q;
    bool r;
    bool s;
    File *targets;
} Options;

typedef enum Command {
    CMD_INVALID = -1,
    CMD_MD5 = 0,
    CMD_SHA256 = 1,
} Command;

typedef void (*OptionHandler)(struct Options *const);

int md5(const Options *const opts);
int sha256(const Options *const opts);

// options.c
Command options_parse(struct Options *const args, char **argv);
void options_cleanup(File *head);

// string.c
int cmp(void *a, void *b);
size_t len(const char *const s);

#endif
