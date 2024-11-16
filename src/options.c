#include "libft.h"
#include "ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>



#define INVALID_COMMAND(cmd)                                                                                           \
    {                                                                                                                  \
        write(STDERR_FILENO, "Invalid command '", 18);                                                                 \
        write(STDERR_FILENO, cmd, ft_strlen(cmd));                                                                     \
        write(STDERR_FILENO, "'; type \"help\" for a list.\n", 28);                                                    \
    }

#define INVALID_OPTION(algo, cmd)                                                                                      \
    {                                                                                                                  \
        char *algo_name;                                                                                               \
                                                                                                                       \
        if (algo == CMD_HELP) {                                                                                        \
            algo_name = "help";                                                                                        \
        } else if (algo == CMD_MD5) {                                                                                  \
            algo_name = "md5";                                                                                         \
        } else {                                                                                                       \
            algo_name = "sha256";                                                                                      \
        }                                                                                                              \
                                                                                                                       \
        write(STDERR_FILENO, algo_name, ft_strlen(algo_name));                                                         \
        write(STDERR_FILENO, ": Unknown option or message digest: ", 36);                                              \
        write(STDERR_FILENO, cmd, ft_strlen(cmd));                                                                     \
        write(STDERR_FILENO, "\n", 1);                                                                                 \
        write(STDERR_FILENO, algo_name, ft_strlen(algo_name));                                                         \
        write(STDERR_FILENO, ": Use -help for summary.\n", 25);                                                        \
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
        free(head->content);
        prev = head;
        head = head->next;
        free(prev);
    }
}

Command
options_get_command(const char *const cmd) {
    if (!ft_strncmp("md5", (void *)cmd, 4)) {
        return CMD_MD5;
    } else if (!ft_strncmp("sha256", (void *)cmd, 7)) {
        return CMD_SHA256;
    } else if (!ft_strncmp("help", (void *)cmd, 5)) {
        return CMD_HELP;
    } else {
        return CMD_INVALID;
    }
}

Command
options_parse(struct Options *const opts, char **av) {
    Command cmd;

    if ((cmd = options_get_command(av[1])) == CMD_INVALID) {
        INVALID_COMMAND(av[1]);
        return CMD_INVALID;
    }

    if (cmd == CMD_HELP && av[2]) {
        INVALID_OPTION(cmd, av[2]);
        return CMD_INVALID;
    }

    for (int idx = 2; av[idx]; ++idx) {
        if (av[idx][0] == '-') {

            const OptionEntry *entry = option_map;
            while (entry->s != NULL && STRCMP(entry->s, av[idx]) && STRCMP(entry->l, av[idx])) {
                entry++;
            }

            if (entry->s == NULL) {
                options_cleanup(opts->targets);
                INVALID_OPTION(cmd, av[idx]);
                return -1;
            }

            entry->handler(opts);

        } else {
            File *new = file_new(av[idx]);
            if (!new) {
                options_cleanup(opts->targets);
                MALLOC_ERROR("could not allocate memory");
                return -1;
            }

            file_add_back(&opts->targets, new);
        }
    }

    if (opts->targets == NULL) {
        opts->targets = file_new("stdin");
        if (!opts->targets) {
            options_cleanup(opts->targets);
            MALLOC_ERROR("could not allocate memory");
            return -1;
        }
    }

    return cmd;
}
