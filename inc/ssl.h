#ifndef SSL_H
#define SSL_H

#include <stdbool.h>

#define STRCMP(a, b) (ft_strncmp(a, b, ft_strlen(a)))

#define MALLOC_ERROR(msg)                                                                                              \
    { perror(msg); }

typedef struct File {
    const char *path;
    void *content;
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
    CMD_HELP = 2,
} Command;

typedef void (*OptionHandler)(struct Options *const);

// md5.c
int md5(Options *const opts);

// sha256.c
int sha256(Options *const opts);

// help.c
int help(Options *const opts);

// options.c
Command options_parse(struct Options *const args, char **argv);
void options_cleanup(File *head);

// file.c
int file_read_all(Options *const opts);

#endif
