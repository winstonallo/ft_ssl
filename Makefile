NAME = ft_ssl

OBJ_DIR = obj
SRC_DIR = src
INC_DIR = inc
LIBFT_DIR = libft

SRCS = 	ssl.c \
		options.c \
		file.c \
		alloc.c \
		display/help.c \
		display/hex.c \
		display/display.c \
		messagedigest/sha256.c \
		messagedigest/md5.c

OBJS = $(addprefix $(OBJ_DIR)/, $(SRCS:.c=.o))

LIBFT = $(LIBFT_DIR)/libft.a
LIBFT_FLAGS = -L$(LIBFT_DIR) -lft

CC = cc
CFLAGS = -Wall -Wextra -Werror -I$(INC_DIR) -I$(LIBFT_DIR)/src/alloc -I$(LIBFT_DIR)/src/mem -I$(LIBFT_DIR)/src/str -I$(LIBFT_DIR)/src/print -I$(LIBFT_DIR)/src/bit
LDFLAGS = $(LIBFT_FLAGS) 

all: $(LIBFT) $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/ssl.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)/bit
	mkdir -p $(OBJ_DIR)/messagedigest
	mkdir -p $(OBJ_DIR)/display

clean:
	rm -rf $(OBJ_DIR)
	$(MAKE) -C $(LIBFT_DIR) clean

fclean: clean
	rm -f $(NAME)
	$(MAKE) -C $(LIBFT_DIR) fclean

re: fclean all

prof:
	FILE_NAME="/tmp/.out" ./tests/generate_random_file.sh
	make CFLAGS="${CFLAGS} -pg -g"
	valgrind --tool=callgrind ./ft_ssl ${ALGO} /tmp/.out
	callgrind_annotate callgrind.out.* >> ${OUTFILE}
	rm callgrind.out.* gmon.out

debug:
	make CFLAGS="${CFLAGS} -g"

$(LIBFT):
	$(MAKE) -C $(LIBFT_DIR)

.PHONY: all clean fclean re