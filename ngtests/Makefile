CC = /usr/bin/gcc
CFLAGS = -Wall

.SUFFIXES:

TESTS = lsnid test fork_test
DEPENDENCIES = nid

DEP_OBJS = $(patsubst %,%.o,$(DEPENDENCIES))

all: $(TESTS)

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@


% : %.o $(DEP_OBJS)
	$(CC) $< $(DEP_OBJS) -o $@

clean:
	rm -rf *.o $(TESTS)
