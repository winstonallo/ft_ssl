#include <stdbool.h>

typedef struct {
    bool p;
    bool q;
    bool r;
    bool s;
} MD5_Args;

typedef void (*MD5_OptionHandler)(MD5_Args *const, const char *const s);

void
md5_handle_p(MD5_Args *const args, const char *const s) {
    args->p = true;
}

void
md5_handle_q(MD5_Args *const args, const char *const s) {
    args->q = true;
}

void
md5_handle_r(MD5_Args *const args, const char *const s) {
    args->r = true;
}

void
md5_handle_s(MD5_Args *const args, const char *const s) {
    args->s = true;
}

typedef struct {
    const char *const option_s;
    const char *const option_l;
    MD5_OptionHandler handler;
} MD5_OptionEntry;

static const MD5_OptionEntry MD5_Options[] = {
    {"-p", "--print",   md5_handle_p},
    {"-q", "--quiet",   md5_handle_q},
    {"-r", "--reverse", md5_handle_r},
    {"-s", "--sum",     md5_handle_s},
};

int
main(int ac, char **av) {
    if (ac < 2) {
        return 2;
    }
}
