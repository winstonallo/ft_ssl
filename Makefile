NAME = ft_ssl

OBJ_DIR = obj
SRC_DIR = src
INC_DIR = inc
LIBFT_DIR = libft

BLOCK_SIZE=$(shell stat -fc %s .)

SRCS = \
		ssl.c \
		options.c \
		file.c \
		alloc.c \
		display/help.c \
		display/hex.c \
		display/display.c \
		messagedigest/sha256.c \
		messagedigest/md5.c \
		cipher/aes256.c \
		cipher/gcm.c

TEST_SRCS = \
		options.c \
		file.c \
		alloc.c \
		display/help.c \
		display/hex.c \
		display/display.c \
		messagedigest/sha256.c \
		messagedigest/md5.c \
		cipher/aes256.c \
		cipher/gcm.c

OBJS = $(addprefix $(OBJ_DIR)/, $(SRCS:.c=.o))
TEST_OBJS = $(addprefix $(OBJ_DIR)/, $(TEST_SRCS:.c=.o))

HEADERS = $(wildcard $(INC_DIR)/*.h) $(wildcard $(LIBFT_DIR)/src/**/*.h)

HEADERS = $(wildcard $(INC_DIR)/*.h) $(wildcard $(LIBFT_DIR)/src/**/*.h)

LIBFT = $(LIBFT_DIR)/libft.a
LIBFT_FLAGS = -L$(LIBFT_DIR) -lft

CC = cc
CFLAGS = -O3 -DFS_BLOCK_SIZE=${BLOCK_SIZE} -Wall -Wextra -Werror \
	-I$(INC_DIR) \
	-I$(LIBFT_DIR)/src/alloc \
	-I$(LIBFT_DIR)/src/mem \
	-I$(LIBFT_DIR)/src/str \
	-I$(LIBFT_DIR)/src/print \
	-I$(LIBFT_DIR)/src/bit
LDFLAGS = $(LIBFT_FLAGS)

test: $(LIBFT) $(TEST_OBJS)
	$(CC) $(CFLAGS) -g $(TEST_OBJS) tests/test.c -o ft_ssl_test $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) | $(OBJ_DIR)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)/messagedigest
	mkdir -p $(OBJ_DIR)/cipher
	mkdir -p $(OBJ_DIR)/display

all: $(LIBFT) $(NAME)

$(NAME): $(OBJS) $(LIBFT)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR)
	$(MAKE) -C $(LIBFT_DIR) clean

fclean: clean
	rm -f $(NAME) ft_ssl_test
	$(MAKE) -C $(LIBFT_DIR) fclean

re: fclean all

prof:
	FILE_NAME="/tmp/.out" ./tests/generate_random_file.sh
	make fclean
	make CFLAGS="${CFLAGS} -pg -g"
	valgrind --tool=callgrind ./ft_ssl ${ALGO} /tmp/.out
	callgrind_annotate callgrind.out.* > ${OUTFILE}
	rm callgrind.out.* gmon.out

debug: CFLAGS = -DFS_BLOCK_SIZE=${BLOCK_SIZE} -Wall -Wextra -Werror -g \
	-I$(INC_DIR) \
	-I$(LIBFT_DIR)/src/alloc \
	-I$(LIBFT_DIR)/src/mem \
	-I$(LIBFT_DIR)/src/str \
	-I$(LIBFT_DIR)/src/print \
	-I$(LIBFT_DIR)/src/bit
debug: all

$(LIBFT):
	$(MAKE) -C $(LIBFT_DIR)

.PHONY: all clean fclean re prof debug test
