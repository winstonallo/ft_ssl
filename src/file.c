#include "libft.h"
#include "ssl.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int
file_read(int fd, File *file) {
    ssize_t total_size = 0;
    file->allocated_bytes = BUFSIZ;

    file->content = ft_calloc(file->allocated_bytes, sizeof(char));
    if (!file->content) {
        perror("initial buffer allocation for message to digest");
        return -1;
    }

    ssize_t bytes_read;
    while ((bytes_read = read(fd, file->content + total_size, file->allocated_bytes - total_size)) > 0) {
        total_size += bytes_read;

        if (total_size >= file->allocated_bytes) {
            file->allocated_bytes *= 2;
            u_int8_t *tmp = buf_realloc(file->content, file->allocated_bytes, total_size);
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

    // This is a monkey patch, since optimizing `buf_realloc` to use `malloc` instead of `ft_calloc`,
    // there has been some uninitialized value issue when constructing the hash output (not influencing
    // the functionality, but better be safe).
    // It ensures that the next 512 bytes after the total size of the message are initialized. I do not
    // go back to `ft_calloc` because removing it resulted in a ~25% speed increase.
    ft_memset(file->content + total_size, 0, 512);

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

        if (head->content) {
            head = head->next;
            continue;
        }

        int fd = open(head->path, O_RDONLY);
        if (fd == -1) {
            ft_printf(STDERR_FILENO, "open '%s': %s\n", head->path, strerror(errno));
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
