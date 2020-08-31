CC ?= cc
CSTD ?= c89
CFLAGS ?= -O3 -march=native -maes -mpclmul -pedantic -Wall -Wextra -Wstrict-prototypes -Wshadow -Wformat=2 -Wstrict-overflow -Wconversion -Wsign-conversion -Wformat-security -Wstack-protector -Werror -std=$(CSTD)
# -g -ggdb -fsanitize=address -mssse3
LDFLAGS ?= $(CFLAGS) 

.PHONY: all clean format

all: test_aes

clean:
	rm -f *.a.c *.o nativecrypto.a test_aes

format:
	astyle -xC80 -t -A1 *.c *.h

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
	
nativecrypto.a: aes.o cypher.o
	$(AR) cr $@ $^

test_aes: test_cypher.o test_aes.o nativecrypto.a
	$(CC) $(LDFLAGS) -o $@ $^
