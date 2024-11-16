#include "libft.h"
#include <stdlib.h>

char *
buf_realloc(char *old_buf, ssize_t new_size) {
    char *new_buf = ft_calloc(new_size, sizeof(char));
    if (!new_buf) {
        return NULL;
    }

    ft_strlcpy(new_buf, old_buf, ft_strlen(old_buf));

    return new_buf;
}
