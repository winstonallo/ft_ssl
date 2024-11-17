#include "libft.h"
#include "ssl.h"
#include <sys/types.h>
#include <unistd.h>

void
display(char *hash, char *algo_name, char *file_path, const struct Options *const opts) {
    (void)opts;

    ft_printf(STDOUT_FILENO, "%s(%s)= %s\n", algo_name, file_path, hash);
}
