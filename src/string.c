#include <stdlib.h>
int
cmp(void *a, void *b) {
    unsigned char *s = a, *t = b;

    while (*s && *t && *s == *t) {
        s++;
        t++;
    }

    return (*(unsigned char *)s - *(unsigned char *)t);
}

size_t
len(const char *const s) {
    size_t len = 0;

    while (s[len]) {
        len++;
    }

    return len;
}
