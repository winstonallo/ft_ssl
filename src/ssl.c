#include "ssl.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>



const Algo algo_map[] = {
    {md5,    "MD5",      33},
    {sha256, "SHA2-256", 65},
};

int
main(int ac, char **av) {
    if (ac < 2) {
        help();
        return EXIT_SUCCESS;
    }

    struct Options opts = {0};

    Command cmd = options_parse(&opts, av);
    if (cmd == CMD_INVALID) {
        options_cleanup(opts.targets);
        return EXIT_FAILURE;
    }

    if (cmd == CMD_HELP) {
        help();
        options_cleanup(opts.targets);
        return EXIT_SUCCESS;
    }

    if (file_read_all(&opts) == -1) {
        options_cleanup(opts.targets);
        return EXIT_FAILURE;
    }

    for (File *it = opts.targets; it; it = it->next) {
        char buf[algo_map[cmd].output_buffer_size];
        algo_map[cmd].hash_func(it, buf);
        display(buf, algo_map[cmd].name, it, &opts);
    }

    options_cleanup(opts.targets);
    return EXIT_SUCCESS;
}
