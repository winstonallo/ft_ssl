#include "ssl.h"

void
options_add_p(Options *const opts) {
    opts->p = true;
}

void
option_add_q(Options *const opts) {
    opts->q = true;
}

void
option_add_r(Options *const opts) {
    opts->r = true;
}

void
option_add_s(Options *const opts) {
    opts->s = true;
}

static const OptionEntry option_map[] = {
    {"-p", "--print",   options_add_p},
    {"-q", "--quiet",   option_add_q },
    {"-r", "--reverse", option_add_r },
    {"-s", "--sum",     option_add_s },
};

int
options_parse(Options *const args, char **argv) {}
