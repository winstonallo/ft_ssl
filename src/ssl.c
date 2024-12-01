#include "ssl.h"
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

typedef int (*Algo)(File *, char *);

static const Algo algo_map[] = {
    md5,    // CMD_MD5
    sha256, // CMD_SHA256
};

static const char *algo_names[] = {"md5\0", "sha256\0"};

static const u_int64_t algo_buffer_sizes[] = {33, 65};

int
main(int ac, char **av) {
    if (ac < 2) {
        help(NULL, NULL);
        return EXIT_SUCCESS;
    }

    struct Options opts = {0};

    Command cmd = options_parse(&opts, av);
    if (cmd == CMD_INVALID) {
        options_cleanup(opts.targets);
        return EXIT_FAILURE;
    }

    if (cmd == CMD_HELP) {
        help(NULL, NULL);
        options_cleanup(opts.targets);
        return EXIT_SUCCESS;
    }

    if (file_read_all(&opts) == -1) {
        options_cleanup(opts.targets);
        return EXIT_FAILURE;
    }

    for (File *it = opts.targets; it; it = it->next) {
        char buf[algo_buffer_sizes[cmd]];
        algo_map[cmd](it, buf);
        display(buf, (char *)algo_names[cmd], (char *)it->path, &opts);
    }

    options_cleanup(opts.targets);
    return EXIT_SUCCESS;
}
