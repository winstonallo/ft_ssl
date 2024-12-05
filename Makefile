NAME = ft_ssl

OBJ_DIR = obj
SRC_DIR = src
INC_DIR = inc
LIBFT_DIR = libft

SRCS = ssl.c md5.c sha256.c options.c file.c help.c alloc.c hex.c display.c bit/rotate.c messagedigest/sha256.c messagedigest/md5.c
OBJS = $(addprefix $(OBJ_DIR)/, $(SRCS:.c=.o))

LIBFT = $(LIBFT_DIR)/libft.a
LIBFT_FLAGS = -L$(LIBFT_DIR) -lft

CC = cc
CFLAGS = -Wall -Wextra -Werror -I$(INC_DIR) -I$(LIBFT_DIR)/include 
LDFLAGS = $(LIBFT_FLAGS) 

all: $(LIBFT) $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/ssl.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)/bit

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