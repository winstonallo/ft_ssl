#include "libft.h"
#include "ssl.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

char *
file_realloc(char *old_buf, ssize_t new_size) {
    char *new_buf = ft_calloc(new_size, sizeof(char));
    if (!new_buf) {
        return NULL;
    }

    ft_strlcpy(new_buf, old_buf, ft_strlen(old_buf));

    return new_buf;
}

char *
file_read(int fd) {
    ssize_t total_size = 0;
    ssize_t allocated = BUFSIZ;

    char *buf = ft_calloc(allocated, sizeof(char));
    if (!buf) {
        perror("initial buffer allocation for message to digest");
        return NULL;
    }

    ssize_t bytes_read;
    while ((bytes_read = read(fd, buf + total_size, allocated - total_size)) > 0) {
        total_size += bytes_read;

        if (total_size >= allocated) {
            allocated *= 2;
            char *tmp = file_realloc(buf, allocated);
            if (!tmp) {
                free(buf);
                perror("buffer reallocation");
                return NULL;
            }
        }
    }

    if (bytes_read == -1) {
        perror("reading message to digest");
        return NULL;
    }

    return buf;
}

int
file_read_all(Options *const opts) {
    File *head = opts->targets;

    if (!STRCMP(head->path, "stdin")) {
        head->content = file_read(STDIN_FILENO);
        if (!head->content) {
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

        head->content = file_read(fd);
        if (!head->content) {
            options_cleanup(opts->targets);
            return -1;
        }

        head = head->next;
    }

    return 0;
}
