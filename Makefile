CC=gcc
CFLAGS=-std=c99 -pedantic -Wall -Wextra -lpcap
EXECUTABLE=flow
VARGS=--tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes
OBJS=flow.o arguments.o

all: clean $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) -o flow $^

flow.o: flow.c
	$(CC) $(CFLAGS) -c $^

arguments.o: arguments.c
	$(CC) $(CFLAGS) -c $^

valgrind: $(EXECUTABLE)
	valgrind $(VARGS) ./$(EXECUTABLE)

clean:
	rm -f $(EXECUTABLE) *.o
