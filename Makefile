CC=gcc
CPP=g++
CFLAGS=-std=c++14 -pedantic -Wall -Wextra -lpcap
EXECUTABLE=flow
VARGS=--tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes
OBJS=flow.o arguments.o

all: clean $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CPP) $(CFLAGS) -o $(EXECUTABLE) $^

flow.o: flow.cpp
	$(CPP) $(CFLAGS) -c $^

arguments.o: arguments.cpp
	$(CPP) $(CFLAGS) -c $^

valgrind: $(EXECUTABLE)
	valgrind $(VARGS) ./$(EXECUTABLE)

clean:
	rm -f $(EXECUTABLE) *.o *.gch
