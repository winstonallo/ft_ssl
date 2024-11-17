#ifndef SSL_H
#define SSL_H

#include <stdbool.h>
#include <sys/types.h>

#define STRCMP(a, b) (ft_strncmp(a, b, ft_strlen(a)))

#define MALLOC_ERROR(msg)                                                                                                                                      \
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

// md5.c
int md5(File *targets, char *buf);

// sha256.c
int sha256(File *targets, char *buf);

// help.c
int help(File *targets, char *buf);

// options.c
Command options_parse(struct Options *const args, char **argv);
void options_cleanup(File *head);

// alloc.c
char *buf_realloc(char *old_buf, ssize_t new_size);

// file.c
int file_read_all(Options *const opts);

#endif
