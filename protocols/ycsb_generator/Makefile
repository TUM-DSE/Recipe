CXX = g++
INCLUDE_PATH = -I/usr/local/include
LD_PATH	= -L/usr/local/lib
FLAGS = -lcityhash -lpthread

example:
	$(CXX) -Wall -g -O3 $(INCLUDE_PATH) $(LD_PATH) generate_traces.cc example.cc -o test $(FLAGS)
