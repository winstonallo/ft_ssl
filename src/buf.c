#include "ssl.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "libft.h"

// char*
// buf_realloc(char* old_buf, ssize_t new_size) {

// }

int
buf_read(Options *opts) {
    File *head = opts->targets;

    while (head) {
        ssize_t total_size = 0;

        int fd = open(head->path, O_RDONLY);
        if (fd == -1) {
            perror("opening message to digest");
            return -1;
        }

        ssize_t allocated = BUFSIZ;
        char *buf = malloc(allocated);
        if (!buf) {
            perror("initial buffer allocation for message to digest");
            return -1;
        }

        ssize_t bytes_read;
        while ((bytes_read = read(fd, buf + total_size, allocated - total_size)) > 0) {
            total_size += bytes_read;

            if (total_size >= allocated) {
                allocated *= 2;
            }
            
            if (bytes_read == -1) {
                perror("reading message to digest");
                return -1;
            }
        }
    }

    return 0;
}
