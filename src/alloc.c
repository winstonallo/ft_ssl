#include "libft.h"
#include <stdlib.h>
#include <sys/types.h>

u_int8_t *
buf_realloc(u_int8_t *old_buf, ssize_t new_size, ssize_t old_size) {
    u_int8_t *new_buf = ft_calloc(new_size, sizeof(u_int8_t));
    if (!new_buf) {
        return NULL;
    }

    ft_memcpy(new_buf, old_buf, old_size);

    free(old_buf);

    return new_buf;
}
