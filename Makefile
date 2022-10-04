CC=gcc
CFLAGS=-std=gnu99 -pedantic -Wall -Wextra -lpcap
NAME=flow

all: run

run:
	$(CC) $(CFLAGS) $(NAME).c -o $(NAME) -lpcap

clean:
	-rm -f *.o $(NAME)