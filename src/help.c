#include "ssl.h"
#include <unistd.h>

int
help(const Options *const opts) {
    (void)opts;

    write(STDERR_FILENO, "help:\n\n", 7);
    write(STDERR_FILENO, "Message Digest commands\n", 24);
    write(STDERR_FILENO, "md5               sha256\n", 25);

    return 0;
}
