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


    if (file->option_s) {
        char to_print[file->content_size + 1];

        ft_memcpy(to_print, file->content, file->content_size);
        to_print[file->content_size] = '\0';
        
        if (opts->r) {
            ft_printf(STDOUT_FILENO, "%s *\"%s\"\n", hash, to_print);
        } else {
            ft_printf(STDOUT_FILENO, "%s(\"%s\")= %s\n", algo_name, to_print, hash);
        }
    } else if (opts->p) {

        char to_print[file->content_size + 1];

        ft_memcpy(to_print, file->content, file->content_size);
        to_print[file->content_size] = '\0';

        if (opts->r) {
            ft_printf(STDOUT_FILENO, "%s *\"%s\"\n", hash, to_print);
        } else {
            ft_printf(STDOUT_FILENO, "%s(\"%s\")= %s\n", algo_name, to_print, hash);
        }

    } else {
        if (opts->r) {
            ft_printf(STDOUT_FILENO, "%s *%s\n", hash, file->path);
        } else {
            ft_printf(STDOUT_FILENO, "%s(%s)= %s\n", algo_name, file->path, hash);
        }
    }


}
