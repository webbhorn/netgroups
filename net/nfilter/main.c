#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

extern int nfilter_init(void);
extern void nfilter_exit(void);
extern int policy_set_init(void);
extern void policy_set_cleanup(void);

static int __init init(void) {
	/* TODO: Check error codes */
	int retcode;
	retcode = nfilter_init();
	retcode = policy_set_init();
	return retcode;
}

static void __exit exit(void) {
	policy_set_cleanup();
	nfilter_exit();
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tim Donegan <donegan@mit.edu>, Webb Horn <webbhorn@mit.edu>, Julian Gonzalez <jugonz97@mit.edu>");
MODULE_DESCRIPTION("6.858 netgroups project");
