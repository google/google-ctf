CXXFLAGS = -O3 --std=c++17
LDLIBS = -lpthread

PRGM  = machine
HDRS := $(wildcard *.h)
SRCS := $(wildcard *.cc)
OBJS := $(SRCS:.cc=.o)

.PHONY: all clean

all: $(PRGM)

$(PRGM): $(OBJS)
	$(CXX) $(OBJS) $(LDLIBS) -o $@

%.o: %.cc $(HDRS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(PRGM)
