#include "libft.h"
#include "ssl.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int add_file(Options *const opts, const char *const arg, bool content);

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
        ft_printf(STDERR_FILENO, "%s: Unknown option for message digest: %s\n%s: Use -help for summary.\n", algo_name, \
                  cmd, algo_name);                                                                                     \
    }

typedef int (*OptionHandler)(struct Options *const, char **, size_t *);

typedef struct {
    const char *s;
    const char *l;
    OptionHandler handler;
} OptionEntry;

static int
add_p(Options *const opts, char **av, size_t *idx) {
    (void)av;
    (void)idx;
    opts->p = true;
    return 0;
}

static int
add_q(Options *const opts, char **av, size_t *idx) {
    (void)av;
    (void)idx;
    opts->q = true;
    return 0;
}

static int
add_r(Options *const opts, char **av, size_t *idx) {
    (void)av;
    (void)idx;
    opts->r = true;
    return 0;
}

static int
add_s(Options *const opts, char **av, size_t *idx) {

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
    file->reallocated = false;
    file->allocated = false;
    file->content = NULL;
    file->option_s = false;

    return file;
}

static void
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

static int
add_file(Options *const opts, const char *const arg, bool content) {
    File *new = file_new(arg);

    if (!new) {
        options_cleanup(opts->targets);
        ft_printf(STDERR_FILENO, "could not allocate list node for `%s`: %s", arg, strerror(errno));
        return -1;
    }

    if (content) {
        new->option_s = true;
        new->content_size = ft_strlen(arg);
        new->content = (uint8_t *)arg;
    }

    file_add_back(&opts->targets, new);
    return 0;
}

static Command
get_command(const char *const cmd) {
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

static int
add_opt(Options *const opts, Command cmd, char **av, size_t *idx) {

    const OptionEntry *entry = option_map;
    while (entry->s != NULL && ft_strncmp(entry->s, av[*idx], 3) && ft_strncmp(entry->l, av[*idx], 10)) {
        entry++;
    }

    if (entry->s == NULL) {
        INVALID_OPTION(cmd, av[*idx]);
        return -1;
    }

    return entry->handler(opts, av, idx);
}

// Cleans up all heap memory allocated for dynamic content (as of now only message
// buffers and their linked list pointers).
// Safety:
// - This does not clean up the Options struct, as it is assumed to be stack
// allocated.
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
// Best called with an Options struct allocated in main, on the stack.
Command
options_parse(struct Options *const opts, char **av) {
    Command cmd;

    if ((cmd = get_command(av[1])) == CMD_INVALID) {
        ft_printf(STDERR_FILENO, "Invalid command: '%s'; type \"./ft_ssl help\" for a list.\n", av[1]);
        return CMD_INVALID;
    }

    if (cmd == CMD_HELP && av[2]) {
        INVALID_OPTION(cmd, av[2]);
        return CMD_INVALID;
    }

    for (size_t idx = 2; av[idx]; ++idx) {
        if (av[idx][0] == '-') {
            if (add_opt(opts, cmd, av, &idx) == -1) {
                return -1;
            }
        } else if (add_file(opts, av[idx], false) == -1) {
            return -1;
        }
    }

    if (opts->targets == NULL && add_file(opts, "stdin", false) == -1) {
        return -1;
    }

    return cmd;
}
