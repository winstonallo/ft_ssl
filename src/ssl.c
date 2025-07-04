#include "ssl.h"
#include "mem.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

const Algo algo_map[] = {
    {md5,    "md5",    "MD5",      33},
    {sha256, "sha256", "SHA2-256", 65},
    {NULL,   NULL,     NULL,       0 },
};

int
main(int ac, char **av) {
    if (ac < 2 || !ft_memcmp(av[1], "help", 5)) {
        help();
        return EXIT_SUCCESS;
    }

    struct Options opts = {0};

    Algo *algo = options_parse(algo_map, &opts, av);
    if (!algo) {
        options_cleanup(opts.targets);
        return EXIT_FAILURE;
    }

    if (file_read_all(&opts) == -1) {
        options_cleanup(opts.targets);
        return EXIT_FAILURE;
    }

    for (File *it = opts.targets; it; it = it->next) {
        if (it->failed) {
            continue;
        }

        char buf[algo->output_buffer_size];

        if (algo->f(it, buf) == -1) {
            continue;
        }

        display(buf, algo->display_name, it, &opts);
    }

    options_cleanup(opts.targets);
    return EXIT_SUCCESS;
}
