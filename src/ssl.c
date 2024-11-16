#include "ssl.h"
#include <bits/getopt_core.h>
#include <stdbool.h>
#include <stdlib.h>

typedef int (*Algo)(Options *const);

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

    algo_map[cmd](&opts);

    options_cleanup(opts.targets);
}
