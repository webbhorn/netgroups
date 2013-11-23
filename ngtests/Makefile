all: lsnid

lsnid: lsnid.o nid.o
	gcc lsnid.o nid.o -o lsnid

lsnid.o: lsnid.c
	gcc -c lsnid.c

nid.o: nid.c
	gcc -c nid.c

clean:
	rm -rf *.o lsnid
