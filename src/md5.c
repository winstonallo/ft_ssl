#include "ssl.h"

int
md5(Options *const opts) {
    (void)opts;

    file_read_all(opts);
    return 0;
}
