#include "ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define INVALID_COMMAND(cmd)                                                                                                                                   \
    {                                                                                                                                                          \
        write(STDERR_FILENO, "Invalid command '", 18);                                                                                                         \
        write(STDERR_FILENO, cmd, len(cmd));                                                                                                                   \
        write(STDERR_FILENO, "'; type \"help\" for a list.", 27);                                                                                              \
    }

#define MALLOC_ERROR(msg) perror(msg)

typedef struct {
    const char *option_s;
    const char *option_l;
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
        printf("%s\n", head->path);
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
        return CMD_INVALID;
    }

    for (int idx = 2; av[idx]; ++idx) {
        if (av[idx][0] == '-') {

            const OptionEntry *entry = option_map;
            while (entry->option_s != NULL && cmp((void *)entry->option_s, av[idx]) && cmp((void *)entry->option_s, av[idx])) {
                entry++;
            }

            if (entry->option_s == NULL) {
                INVALID_COMMAND(av[idx]);
                options_cleanup(opts->to_hash);
                return -1;
            }

            entry->handler(opts);
        } else {
            File *new = file_new(av[idx]);
            if (!new) {
                MALLOC_ERROR("");
                options_cleanup(opts->to_hash);
                return -1;
            }

            file_add_back(&opts->to_hash, new);
        }
    }
    return cmd;
}
