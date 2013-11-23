all: lsnid tests

lsnid: lsnid.o nid.o
	gcc lsnid.o nid.o -o lsnid

tests: test.o nid.o
	gcc test.o nid.o -o test

lsnid.o: lsnid.c
	gcc -c lsnid.c

test.o: test.c
	gcc -c test.c

nid.o: nid.c
	gcc -c nid.c

clean:
	rm -rf *.o lsnid test
