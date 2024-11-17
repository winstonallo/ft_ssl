#include "ssl.h"
#include "libft.h"
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

typedef int (*Algo)(File *, char *);

static const Algo algo_map[] = {
    md5,    // CMD_MD5
    sha256, // CMD_SHA256
    help,   // CMD_HELP
};

int
main(int ac, char **av) {
    if (ac < 2) {
        return 2;
    }

    struct Options opts = {0};

    Command cmd = options_parse(&opts, av);
    if (cmd == CMD_INVALID) {
        options_cleanup(opts.targets);
        return EXIT_FAILURE;
    }

    if (cmd != CMD_HELP && file_read_all(&opts) == -1) {
        options_cleanup(opts.targets);
        return EXIT_FAILURE;
    }

    char buf[33];

    algo_map[cmd](opts.targets, buf);

    ft_printf(STDOUT_FILENO, "%s\n", buf);

    options_cleanup(opts.targets);
}
