#ifndef SSL_H
#define SSL_H

#include <stdbool.h>

typedef struct {
    bool p;
    bool q;
    bool r;
    bool s;
} Options;

typedef void (*OptionHandler)(Options *const);

typedef struct {
    const char *id_s;
    const char *id_l;
    OptionHandler handler;
} OptionEntry;

int md5(void *buf);
int sha256(void *buf);
int options_parse(Options *const args, char **argv);

#endif
