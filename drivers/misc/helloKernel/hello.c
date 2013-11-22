#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gonzalez");
MODULE_DESCRIPTION("Hello world module");

static int __init hello_init(void)
{
	printk(KERN_INFO "Hello, kernel!\n");
	return 0; // 0 means kernel module loaded successfully
}

static void __exit hello_cleanup(void)
{
	printk(KERN_INFO "Cleaning up hello kernel module!\n");
}

module_init(hello_init);
module_exit(hello_cleanup);
