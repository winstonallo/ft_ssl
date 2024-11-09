#include "ssl.h"
#include <stdbool.h>
#include <stdlib.h>

int
main(int ac, char **av) {
    if (ac < 2) {
        return 2;
    }

    struct Options opts = {0};

    if (options_parse(&opts, av) == -1) {
        options_cleanup(opts.to_hash);
        return EXIT_FAILURE;
    }

    options_cleanup(opts.to_hash);
}
