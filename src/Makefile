# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lmbedtls -lmbedcrypto -lmbedx509

# Source and output
SRCS = main.c puf_verify.c utils.c
OBJS = $(SRCS:.c=.o)
TARGET = puf_verify_app

# Default target
all: $(TARGET)

# Linking
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile .c to .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJS) $(TARGET)