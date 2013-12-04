/* Character driver test
 * Uses code from Linux Devices Drivers, 3rd edition &
 * http://pete.akeo.ie/2011/08/writing-linux-device-driver-for-kernels.html
 * Julian Gonzalez, 6.858 Final Project Fall 2013
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/kfifo.h>
#include <linux/cdev.h>

#define PROG_NAME "simpleCharDriver"
#define MAX_MSGS 64

// global vars: sue me
static dev_t device_nums;
static struct class *fifo_device_class;
static struct cdev *fifo_cdev;
static DEFINE_KFIFO(inputFIFO, char, MAX_MSGS);
// from example: keep track of message lengths
static unsigned int fifo_msg_lens[MAX_MSGS];
// indices for message len array
static int msg_len_rd, msg_len_write;


static ssize_t read_dummy(struct file *filp, char __user *buf,
		size_t count, loff_t *f_pos) {
	int return_code;
	unsigned int bytes_copied;
	
	if (kfifo_is_empty(&inputFIFO)) {
		printk(KERN_INFO "FIFO was empty!");
	}

	// Send data to user space, keep return code, bytes copied and update pointer
	// in message length array
	return_code = kfifo_to_user(&inputFIFO, buf, fifo_msg_lens[msg_len_rd],
		&bytes_copied);	
	msg_len_rd = (msg_len_rd + 1) % MAX_MSGS;

	// Return any error, or else the number of bytes pushed to userland
	return return_code ? return_code : bytes_copied;
}

static int open_dummy(struct inode *inode, struct file *filp) {
	if ( ((filp->f_flags & O_ACCMODE) == O_WRONLY) ||
		((filp->f_flags & O_ACCMODE) == O_RDWR) ) {
  		printk(KERN_INFO "Cannot write to this file!!!\n");
  		return -EACCES;
	}

	return 0;
}

static int release_dummy(struct inode *inode, struct file *filp) {
	return 0;
}

// This defines how the file in /dev is arranged
static struct file_operations f_ops = {
	.open = open_dummy,
	.read = read_dummy,
	.release = release_dummy
};

// Called on load of kernel module
static int __init cd_tester_init(void)
{
	int return_val;
	printk(KERN_INFO "%s has started to init\n", PROG_NAME);
	
	// Alloc the device numbers
	return_val = alloc_chrdev_region(&device_nums, 0, 1, PROG_NAME);
	if (return_val < 0) {
		goto err;
	}

	// Need to register the device in a class (virtual device here)	
	if ((fifo_device_class = class_create(THIS_MODULE, "char_dev_class")) == NULL) {
		return_val = -1;
		goto err_class_create;
	}

	// Now, create a device file (in /dev)
	if (device_create(fifo_device_class, NULL, device_nums, NULL, PROG_NAME) == NULL) {
		return_val = -1;
		goto err_dev_create;
	}	
		
	// Need to register a character device
	// Do this by allocing/initing a cdev struct
	fifo_cdev = cdev_alloc();
	cdev_init(fifo_cdev, &f_ops);
	fifo_cdev->owner = THIS_MODULE;

	// Add device to kernel
	return_val = cdev_add(fifo_cdev, device_nums, 1);
	if (return_val >= 0) {
		return 0; // setup OK
	}

err_cdev_add:
	device_destroy(fifo_device_class, device_nums);
err_dev_create:
	class_destroy(fifo_device_class);
err_class_create:
	unregister_chrdev_region(device_nums, 1);
err:	
	printk(KERN_INFO "%s exited during initialization\n", PROG_NAME);
	return return_val;	
}

// Called on unload of kernel module

static void __exit cd_tester_cleanup(void)
{
	cdev_del(fifo_cdev);
	device_destroy(fifo_device_class, device_nums);
	class_destroy(fifo_device_class);
	unregister_chrdev_region(device_nums, 1);
	printk(KERN_INFO "%s has cleaned up and exited\n", PROG_NAME);
}

module_init(cd_tester_init);
module_exit(cd_tester_cleanup);

// Module info
MODULE_AUTHOR("Julian Gonzalez");
MODULE_DESCRIPTION("Simple FIFO character device");
MODULE_LICENSE("GPL");
