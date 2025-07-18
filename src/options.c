#include "mem.h"
#include "print.h"
#include "ssl.h"
#include "str.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int add_file(Options *const opts, const char *const arg, bool content);

typedef int (*OptionHandler)(struct Options *const, char **, uint64_t *);

typedef struct {
    const char *s;
    const char *l;
    OptionHandler handler;
} OptionEntry;

static int
add_p(Options *const opts, char **av, uint64_t *idx) {
    (void)av;
    (void)idx;
    opts->p = true;
    return 0;
}

static int
add_q(Options *const opts, char **av, uint64_t *idx) {
    (void)av;
    (void)idx;
    opts->q = true;
    return 0;
}

static int
add_r(Options *const opts, char **av, uint64_t *idx) {
    (void)av;
    (void)idx;
    opts->r = true;
    return 0;
}

static int
add_s(Options *const opts, char **av, uint64_t *idx) {

    if (!av[(*idx) + 1]) {
        ft_printf(STDERR_FILENO, "ft_ssl: -s option needs to be followed by an input string\n");
        return -1;
    }

    *idx += 1;

    return add_file(opts, av[*idx], true);
}

static const OptionEntry option_map[] = {
    {"-p", "--print",   add_p},
    {"-q", "--quiet",   add_q},
    {"-r", "--reverse", add_r},
    {"-s", "--sum",     add_s},
    {NULL, NULL,        NULL },
};

static File *
file_new(const char *const path) {

    File *file = malloc(sizeof(File));
    if (!file) {
        return NULL;
    }

    file->path = path;
    file->next = NULL;
    file->allocated_bytes = 0;
    file->content_size = 0;
    file->flags = 0;
    file->content = NULL;

    return file;
}

static void
file_add_back(File **head, File *new) {
    if (!*head) {
        *head = new;
        return;
    }

    File *it = *head;

    while (it->next) {
        it = it->next;
    }

    it->next = new;
}

static int
add_file(Options *const opts, const char *const arg, bool content) {
    File *new = file_new(arg);

    if (!new) {
        options_cleanup(opts->targets);
        ft_printf(STDERR_FILENO, "could not allocate list node for `%s`: %s", arg, strerror(errno));
        return -1;
    }

    if (content) {
        new->set_option_s;
        new->content_size = ft_strlen(arg);
        new->content = (uint8_t *)arg;
    }

    file_add_back(&opts->targets, new);
    return 0;
}

static Algo *
get_command(const Algo *const algo_map, const char *const cmd) {
    for (Algo *entry = (Algo *)algo_map; entry->f != NULL; ++entry) {
        if (!ft_memcmp(entry->cmd, cmd, ft_strlen(entry->cmd) + 1)) {
            return entry;
        }
    }

    return NULL;
}

static int
add_opt(Options *const opts, Algo *cmd, char **av, uint64_t *idx) {

    const OptionEntry *entry = option_map;
    while (entry->s != NULL && ft_memcmp(entry->s, av[*idx], 3) && ft_memcmp(entry->l, av[*idx], 10)) {
        entry++;
    }

    if (entry->s == NULL) {
        ft_printf(STDERR_FILENO, "%s: Unknown option for message digest: %s\n%s: Use -help for summary.\n", cmd->cmd, av[*idx], cmd->cmd);
        return -1;
    }

    return entry->handler(opts, av, idx);
}

// Cleans up all heap memory allocated for dynamic content (as of now only message
// buffers and their linked list pointers).
void
options_cleanup(File *head) {
    File *prev;

    while (head) {

        if (head->allocated) {
            free(head->content);
        }

        prev = head;
        head = head->next;
        free(prev);
    }
}

// Parses through the argument vector and fills `opts` with the resulting options and
// message paths.
Algo *
options_parse(const Algo *const algo_map, struct Options *const opts, char **av) {
    Algo *algo;

    if (!(algo = get_command(algo_map, av[1]))) {
        ft_printf(STDERR_FILENO, "Invalid command: '%s'; type \"./ft_ssl help\" for a list.\n", av[1]);
        return NULL;
    }

    for (uint64_t idx = 2; av[idx]; ++idx) {
        if (av[idx][0] == '-') {
            if (add_opt(opts, algo, av, &idx) == -1) {
                return NULL;
            }
        } else if (add_file(opts, av[idx], false) == -1) {
            return NULL;
        }
    }

    if (opts->targets == NULL && add_file(opts, "stdin", false) == -1) {
        return NULL;
    }

    return algo;
}
