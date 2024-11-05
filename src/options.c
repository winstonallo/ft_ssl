#include "ssl.h"

void
options_add_p(Options *const opts) {
    opts->p = true;
}

void
options_add_q(Options *const opts) {
    opts->q = true;
}

void
options_add_r(Options *const opts) {
    opts->r = true;
}

void
options_add_s(Options *const opts) {
    opts->s = true;
}

static const OptionEntry option_map[] = {
    {"-p", "--print",   options_add_p},
    {"-q", "--quiet",   options_add_q },
    {"-r", "--reverse", options_add_r },
    {"-s", "--sum",     options_add_s },
};

int
options_parse(Options *const args, char **argv) {}
