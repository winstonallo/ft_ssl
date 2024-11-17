#include "ssl.h"
#include <unistd.h>

int
help(File *targets, char *buf) {
    (void)targets;
    (void)buf;

    write(STDERR_FILENO, "help:\n\n", 7);
    write(STDERR_FILENO, "Message Digest commands\n", 24);
    write(STDERR_FILENO, "md5               sha256\n", 25);

    return 0;
}
