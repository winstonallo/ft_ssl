#include "str.h"
#include <unistd.h>

#define HELP                                                                                                                                                   \
    "help\n\n"                                                                                                                                                 \
    "./ft_ssl [command] [options] [file...]\n\n"                                                                                                               \
    "General options:\n"                                                                                                                                       \
    "-p | --print        echo STDIN to STDOUT and append the checksum to STDOUT\n"                                                                             \
    "-q | --quiet        quiet mode (only print the checksum)\n"                                                                                               \
    "-r | --reverse      reverse the format of the output\n"                                                                                                   \
    "-s | --sum          print the sum of the given string\n\n"                                                                                                \
    "Message Digest commands\n"                                                                                                                                \
    "md5               sha256\n\0"

void
help() {
    write(STDERR_FILENO, HELP, ft_strlen(HELP));
}
