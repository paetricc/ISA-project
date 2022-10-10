CPP=g++
CFLAGS=-std=c++14 -pedantic -Wall -Wextra
EXECUTABLE=flow
VARGS=--tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes
OBJS=flow.o arguments.o packet.o

all: clean $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CPP) $(CFLAGS) -o $(EXECUTABLE) $^ -lpcap

flow.o: flow.cpp
	$(CPP) $(CFLAGS) -c $^

arguments.o: arguments.cpp
	$(CPP) $(CFLAGS) -c $^

packet.o: packet.cpp
	$(CPP) $(CFLAGS) -c $^

valgrind: $(EXECUTABLE)
	valgrind $(VARGS) ./$(EXECUTABLE)

clean:
	rm -f $(EXECUTABLE) *.o *.gch
