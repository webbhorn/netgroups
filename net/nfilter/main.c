#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

extern int nfilter_init(void);
extern void nfilter_exit(void);

static int init(void) {
	return nfilter_init();
}

static void exit(void) {
	nfilter_exit();
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tim Donegan <donegan@mit.edu>, Webb Horn <webbhorn@mit.edu>, Julian Gonzalez <>");
MODULE_DESCRIPTION("858 proj fix later");
