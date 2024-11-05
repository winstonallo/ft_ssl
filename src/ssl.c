#include "ssl.h"
#include <stdbool.h>

int
cmp(void *a, void *b) {
    unsigned char *s = a, *t = b;

    while (*s && *t && *s == *t) {
        s++;
        t++;
    }

    return (*(unsigned char *)s - *(unsigned char *)t);
}

int
main(int ac, char **av) {
    if (ac < 2) {
        return 2;
    }

    if (!cmp(av[1], "md5")) {
        return md5(av[2]);
    } else if (!cmp(av[1], "sha256")) {
        return sha256(av[2]);
    }

    return 1;
}
