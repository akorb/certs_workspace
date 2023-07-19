CC=gcc

.PHONY: all
all:
	$(CC) -o main -I /usr/include/mbedtls2 main.c
