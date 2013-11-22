#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>

#define procfs_name "helloKernel"

// Describes our proc file
struct proc_dir_entry *hello_proc_file;

// This is used when something reads our proc file.
// See the device driver book for more info.
int procfile_read(char *buffer, char **buffer_loc, off_t offset, int buffer_length,
	int *eof, void *data)
{
	int return_code;
	printk(KERN_INFO "procfile_read called for %s\n", procfs_name);

	// If offset > 0, then we have nothing else to print to screen.
	if (offset > 0) {
		return_code = 0;
	} else {
		// this is the first call to procfile_read
		return_code = sprintf(buffer, "hello /proc!\n");
	}

	return return_code;
}

// File options to define what function is called on read
static const struct file_operations hello_proc_fops = {
 	.owner = THIS_MODULE,
	.read = procfile_read,
};

// Called on loading of kernel module
static int __init hello_init(void)
{
	printk(KERN_INFO "Hello, kernel!\n");
	
	// Create proc file
	hello_proc_file = proc_create(procfs_name, 0, NULL, &hello_proc_fops);
	if (hello_proc_file == NULL) {
		remove_proc_entry(procfs_name, NULL);
		printk(KERN_INFO "Could not initialize %s in /proc\n", procfs_name);
		return -ENOMEM;
	}

	printk(KERN_INFO "%s initialized successfully", procfs_name);
	return 0; // 0 means kernel module loaded successfully
}

static void __exit hello_cleanup(void)
{
	remove_proc_entry(procfs_name, NULL);
	printk(KERN_INFO "Cleaning up hello kernel module!\n");
}

module_init(hello_init);
module_exit(hello_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gonzalez");
MODULE_DESCRIPTION("Hello world module");
