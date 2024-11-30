#include "libft.h"
#include "ssl.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int
file_read(int fd, File *file) {
    ssize_t total_size = 0;
    ssize_t allocated = BUFSIZ;

    file->content = ft_calloc(allocated, sizeof(char));
    if (!file->content) {
        perror("initial buffer allocation for message to digest");
        return -1;
    }

    ssize_t bytes_read;
    while ((bytes_read = read(fd, file->content + total_size, allocated - total_size)) > 0) {
        total_size += bytes_read;

        // printf("buf (len %zu)\n", total_size);
        if (total_size >= allocated) {
            allocated *= 2;
            u_int8_t *tmp = buf_realloc(file->content, allocated, total_size);
            if (!tmp) {
                free(file->content);
                perror("buf_realloc");
                return -1;
            }
            file->content = tmp;
        }
    }

    if (bytes_read == -1) {
        perror("reading message to digest");
        return -1;
    }
    file->content_size = total_size;
    return 0;
}

int
file_read_all(Options *const opts) {
    File *head = opts->targets;

    if (!STRCMP(head->path, "stdin")) {
        if (file_read(STDIN_FILENO, head) == -1) {
            options_cleanup(opts->targets);
            return -1;
        }
        return 0;
    }

    while (head) {
        int fd = open(head->path, O_RDONLY);
        if (fd == -1) {
            perror("opening message to digest");
            return -1;
        }

        if (file_read(fd, head) == -1) {
            options_cleanup(opts->targets);
            return -1;
        }

        head = head->next;
    }

    return 0;
}
