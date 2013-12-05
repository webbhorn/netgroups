obj-m += nfilter.o
nfilter-objs := nfilter-main.o ngpolicy.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
