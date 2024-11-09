#include "ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define INVALID_COMMAND(cmd)                                                                                           \
    {                                                                                                                  \
        write(STDERR_FILENO, "Invalid command '", 18);                                                                 \
        write(STDERR_FILENO, cmd, len(cmd));                                                                           \
        write(STDERR_FILENO, "'; type \"help\" for a list.\n", 28);                                                      \
        return CMD_INVALID;                                                                                            \
    }

#define INVALID_OPTION(algo, cmd)                                                                                      \
    {                                                                                                                  \
        char *algo_name = algo == CMD_MD5 ? "md5" : "sha256";                                                          \
                                                                                                                       \
        write(STDERR_FILENO, algo_name, len(algo_name));                                                               \
        write(STDERR_FILENO, ": Unknown option or message digest: ", 36);                                              \
        write(STDERR_FILENO, cmd, len(cmd));                                                                           \
        write(STDERR_FILENO, "\n", 1);                                                                                 \
        write(STDERR_FILENO, algo_name, len(algo_name));                                                               \
        write(STDERR_FILENO, ": Use -help for summary.\n", 25);                                                        \
        return -1;                                                                                                     \
    }

typedef struct {
    const char *s;
    const char *l;
    OptionHandler handler;
} OptionEntry;

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
    {"-q", "--quiet",   options_add_q},
    {"-r", "--reverse", options_add_r},
    {"-s", "--sum",     options_add_s},
    {NULL, NULL,        NULL         },
};

File *
file_new(const char *const path) {
    File *file = malloc(sizeof(File));
    if (!file) {
        return NULL;
    }

    file->path = path;
    file->next = NULL;

    return file;
}

void
file_add_back(File **head, File *new) {
    if (!head || !*head) {
        *head = new;
        return;
    }

    File *it = *head;

    while (it->next) {
        it = it->next;
    }

    it->next = new;
}

void
options_cleanup(File *head) {
    File *prev;

    while (head) {
        prev = head;
        head = head->next;
        free(prev);
    }
}

Command
options_parse(struct Options *const opts, char **av) {
    Command cmd;

    if (!cmp("md5", av[1])) {
        cmd = CMD_MD5;
    } else if (!cmp("sha256", av[1])) {
        cmd = CMD_SHA256;
    } else {
        INVALID_COMMAND(av[1]);
    }

    for (int idx = 2; av[idx]; ++idx) {
        if (av[idx][0] == '-') {

            const OptionEntry *entry = option_map;
            while (entry->s != NULL && cmp((void *)entry->s, av[idx]) && cmp((void *)entry->l, av[idx])) {
                entry++;
            }

            if (entry->s == NULL) {
                options_cleanup(opts->targets);
                INVALID_OPTION(cmd, av[idx]);
            }

            entry->handler(opts);
        } else {
            File *new = file_new(av[idx]);
            if (!new) {
                options_cleanup(opts->targets);
                MALLOC_ERROR("");
            }

            file_add_back(&opts->targets, new);
        }
    }
    return cmd;
}
