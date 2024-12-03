#include "libft.h"
#include "ssl.h"
#include <sys/types.h>
#include <unistd.h>

void
display(char *hash, char *algo_name, File *file, const struct Options *const opts) {
    ssize_t len = opts->p ? file->content_size : (ssize_t)ft_strlen(file->path);
    char to_print[len];

    if (opts->p) {
        ft_memcpy(to_print, file->content, len);
    } else {
        ft_memcpy(to_print, file->path, len);
    }
    to_print[file->content_size - 1] = '\0';

    ft_printf(STDOUT_FILENO, "%s(%s)= %s\n", algo_name, to_print, hash);
}
