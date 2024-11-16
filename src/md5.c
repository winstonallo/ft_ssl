#include "libft.h"
#include "ssl.h"

int
md5(Options *const opts) {
    (void)opts;

    for (File* tmp = opts->targets; tmp; tmp=tmp->next) {
        ft_printf("path: %s\ncontent:\n%s", tmp->path, tmp->content);
    }

    return 0;
}
