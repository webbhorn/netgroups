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
struct device* sysfs_device;
static struct class *fifo_device_class;
static struct cdev *fifo_cdev;
static DEFINE_KFIFO(inputFIFO, char, MAX_MSGS);
static DEFINE_MUTEX(kfifo_mutex);
// from example: keep track of message lengths
static ssize_t fifo_msg_lens[MAX_MSGS];
// indices for message len array
static int msg_len_rd, msg_len_write;

static ssize_t read_dummy(struct file *filp, char __user *buf,
		size_t count, loff_t *f_pos) {
	int return_code;
	ssize_t bytes_copied;
	
	if (kfifo_is_empty(&inputFIFO)) {
		msg_len_rd = 0;
		printk(KERN_INFO "FIFO was empty!");
	} else if (msg_len_rd + 1 == msg_len_write) {
		printk(KERN_INFO "read entire buffer");
		msg_len_rd = 0;
		return 0;
	}

	// Send data to user space, keep return code, bytes copied and update pointer
	// in message length array
	return_code = kfifo_to_user(&inputFIFO, buf, fifo_msg_lens[msg_len_rd],
		&bytes_copied);	
	msg_len_rd = (msg_len_rd + 1);

	// Return any error, or else the number of bytes pushed to userland
	return return_code ? return_code : bytes_copied;
}

static int open_dummy(struct inode *inode, struct file *filp) {
	if ( ((filp->f_flags & O_ACCMODE) == O_WRONLY) ||
		((filp->f_flags & O_ACCMODE) == O_RDWR) ) {
  		printk(KERN_INFO "Cannot write to this file!!!\n");
  		return -EACCES;
	}

	// ask mutex for lock
	if (!mutex_trylock(&kfifo_mutex)) {
		printk(KERN_INFO "Queue access is denied: already open in some other process\n");
		return -EBUSY;
	}

	return 0;
}

static int release_dummy(struct inode *inode, struct file *filp) {
	// release the queue's mutex
	mutex_unlock(&kfifo_mutex);

	return 0;
}

// This defines how the file in /dev is arranged
static struct file_operations f_ops = {
	.open = open_dummy,
	.read = read_dummy,
	.release = release_dummy
};

// Writing to queue using sysfs
static ssize_t sysfile_add_to_kfifo(struct device* dev, struct device_attribute* attr,
	const char* buf, size_t count) {
	ssize_t copied;
	
	if (kfifo_avail(&inputFIFO) < count) {
		printk(KERN_INFO "Not enough space on KFIFO queue, sorry\n");
		return -ENOSPC;
	} else if ((msg_len_write + 1) == MAX_MSGS) {
		// Table is full
		printk(KERN_INFO "KFIFO queue is full. Clear it before inserting.\n");
		return -ENOSPC;
	}

	// buf holds the text to insert into the KFIFO already!
	copied = kfifo_in(&inputFIFO, buf, count);
        fifo_msg_lens[msg_len_write] = copied;
	
	// update our write index
	msg_len_write = (msg_len_write + 1); 	

	return copied;
}

// Clear queue using sysfs
static ssize_t sysfile_clear_kfifo(struct device* dev, struct device_attribute* attr,
	const char* buf, size_t count) {
	
	// Just clear the queue, returning the count arg provided
	kfifo_reset(&inputFIFO);
	msg_len_rd = 0;
	msg_len_write = 0;

	return count;
}

// Declare the sysfs methods used
static DEVICE_ATTR(fifo, S_IWUSR, NULL, sysfile_add_to_kfifo);
static DEVICE_ATTR(reset, S_IWUSR, NULL, sysfile_clear_kfifo);

// Called on load of kernel module
static int __init cd_tester_init(void) {
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
	sysfs_device = device_create(fifo_device_class, NULL, device_nums, NULL, PROG_NAME);
	if (sysfs_device == NULL) {
		return_val = -1;
		goto err_dev_create;
	}	

	// Add files in /sys for adding and resetting the queue
	return_val = device_create_file(sysfs_device, &dev_attr_fifo);
	if (return_val < 0) {
		printk(KERN_INFO "%s failed to create the fifo write file...\n", PROG_NAME);
	}
	return_val = device_create_file(sysfs_device, &dev_attr_reset);
	if (return_val < 0) {
		printk(KERN_INFO "%s failed to create the fifo reset file...\n", PROG_NAME);
	}

	// Need to register a character device
	// Do this by allocing/initing a cdev struct
	fifo_cdev = cdev_alloc();
	cdev_init(fifo_cdev, &f_ops);
	fifo_cdev->owner = THIS_MODULE;

	// Add device to kernel
	return_val = cdev_add(fifo_cdev, device_nums, 1);
	if (return_val < 0) {
		goto err_cdev_add;
	}

	// Finish setup
	INIT_KFIFO(inputFIFO);
	msg_len_rd = 0;
	msg_len_write = 0;
	return 0; // setup OK, else, destroy everything created

err_cdev_add:
	device_remove_file(sysfs_device, &dev_attr_reset);
	device_remove_file(sysfs_device, &dev_attr_fifo);
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

static void __exit cd_tester_cleanup(void) {
	mutex_destroy(&kfifo_mutex);
	cdev_del(fifo_cdev);
	device_remove_file(sysfs_device, &dev_attr_reset);
	device_remove_file(sysfs_device, &dev_attr_fifo);
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
