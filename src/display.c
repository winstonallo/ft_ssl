#include "libft.h"
#include "ssl.h"
#include <sys/types.h>
#include <unistd.h>

void
display(char *hash, char *algo_name, File *file, const struct Options *const opts) {
    if (opts->q) {
        ft_printf(STDOUT_FILENO, "%s\n", hash);
        return;
    }

    ssize_t len = opts->p ? file->content_size : (ssize_t)ft_strlen(file->path);
    char to_print[len];

    if (opts->p) {
        ft_memcpy(to_print, file->content, len);
    } else {
        ft_memcpy(to_print, file->path, len);
    }

    to_print[len] = '\0';

    if (opts->r) {
        ft_printf(STDOUT_FILENO, "%s *%s\n", hash, to_print);
    } else {
        ft_printf(STDOUT_FILENO, "%s(%s)= %s\n", algo_name, to_print, hash);
    }
}
