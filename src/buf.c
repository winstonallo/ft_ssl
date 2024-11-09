#include "ssl.h"
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

int
buf_read(Options *opts) {
    File *head = opts->targets;

    while (head) {
        int fd = open(head->path, O_RDONLY);
        if (fd == -1) {
            return -1;
        }

        size_t allocated = 1000;
        head->content = malloc(allocated);
        if (!head->content) {
            MALLOC_ERROR("msg")
        }
    }

    return 0;
}
