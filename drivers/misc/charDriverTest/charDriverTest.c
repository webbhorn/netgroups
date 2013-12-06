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
#include <linux/string.h>
#include <linux/uidgid.h>
#include <uapi/linux/ip.h>

#define PROG_NAME "simpleCharDriver"
#define MAX_MSGS 64
#define MAX_IPs 64

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

__be32 make_ipaddr(__u8 b1, __u8 b2, __u8 b3, __u8 b4) {
        __be32 addr = 0;
        addr |= b4;
        addr = addr << 8;
        addr |= b3;
        addr = addr << 8;
        addr |= b2;
        addr = addr << 8;
        addr |= b1;
        return addr;
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
	
	// STRING CONSTANTS...refactor these into a .h file sometime soon
	const char * set_prefix = "set";
	const char * get_prefix = "get";
	const char * mode_blacklist = "b";
	const char * mode_whitelist = "w";
	
	int policy_mode = 0;
	/* 0 is unset, 1 is blacklist, 2 whitelist */	

	// check set prefix
	if ( strnicmp(buf, set_prefix, strlen(set_prefix)) != 0 ) {
		printk("invalid prefix found!\n");
		goto err;
	}	
	// buf holds the text to parse for a policy to query
	
	// get the uid
	char *uid = strchr(buf, ' ');
	if (!uid) {
		printk(KERN_INFO "UID not found\n");
		goto err;
	}
	*uid = '\0';
	uid++;
	
	// get the nid
	char *nid = strchr(uid, ' ');
	if (!nid) {
		printk(KERN_INFO "NID not found\n");
		goto err;
	}
	*nid = '\0';
	nid++;

	// get b/w bit
	char *mode = strchr(nid, ' ');
	if (!mode) {
		printk(KERN_INFO "Policy mode not found\n");
		goto err;
	}
	*mode = '\0';
	mode++;

	// now, parse UID/NID
	// The following code depends on the fact that
	// uid_t and gid_t are unsigned ints
	uid_t uid_val;
	if (kstrtouint(uid, 10, &uid_val) != 0) {
		printk(KERN_INFO "uid could not be parsed\n");
		goto err;
	}
	printk(KERN_INFO "uid is: %u\n", uid_val);

	gid_t nid_val;
	if (kstrtouint(nid, 10, &nid_val) != 0) {
		printk(KERN_INFO "nid could not be parsed\n");
		goto err;
	}
	printk(KERN_INFO "nid is: %u\n", nid_val);

	// parse policy mode: blacklist or whitelist
	if (strnicmp(mode, mode_blacklist, strlen(mode_blacklist)) == 0) {
	policy_mode = 1;
	mode = mode + strlen(mode_blacklist) + 1;
	} else if (strnicmp(mode, mode_whitelist, strlen(mode_whitelist)) == 0) {
	policy_mode = 2;
	mode = mode + strlen(mode_whitelist) + 1;
	} else {
	printk(KERN_INFO "policy mode could not be parsed\n");
	goto err;
	}
	printk(KERN_INFO "Policy mode is:%d\n", policy_mode);
	
	// following mode is a list of IP addresses
	// parse them in a loop and save them to a local var
	// need them as unsigned ints (specifically __u8's)
	__be32 ip_addrs[MAX_IPs];
	
	char *ip = mode;
	char *end_of_input = buf + count;
	printk(KERN_INFO "ip is now: %s\n", ip);
	int ip_i=0;
	for (ip_i=0; ; ip_i++) {
		// split input
		char *end_of_ip = strchr(ip, ' ');
		if (end_of_ip) {
			// null terminate to allow strchr, etc. to work on intermediate strings
			*end_of_ip = '\0';	
		} else {
			// if end_of_ip is null we're at the end of our input string
			end_of_ip = end_of_input;
		}

		// now, from ip to end_of_ip is the ip addr
		// split by '.' (this is ipv4 only)
		char *octal_start = ip;
		__u8 octals[4];
		int octal_i = 0;
		for (octal_i=0; octal_i<4; octal_i++) {
			char *end_of_octal = strchr(octal_start, '.');
			if (!end_of_octal) {
				// can be last octal
				if (octal_i != 3) { 
					printk(KERN_INFO "Octal was: %s\n", octal_start);
					printk(KERN_INFO "IP octal incorrectly formatted, quitting...\n");
					goto err;
				}

				// no '.' at end, just mark end as end of IP
				end_of_octal = end_of_ip;
			} else {
				*end_of_octal = '\0'; // null terminate to use kstrtouint
			}

			// Now, convert to __u8
			__u8 octal_val;
			printk(KERN_INFO "octal start is: %s\n", octal_start);
			if (kstrtouint(octal_start, 10, &octal_val) != 0) {
				printk(KERN_INFO "octal could not be parsed correctly\n");
				goto err;
			}
			// Now, store in octals
			octals[octal_i] = octal_val;			
			octal_start = end_of_octal + 1;
			printk(KERN_INFO "octal val was: %d\n", octal_val);
		}
		
		// convert octals to a _be32 and store
		__be32 parsed_IP = make_ipaddr(octals[0], octals[1], octals[2], octals[3]);
		ip_addrs[ip_i] = parsed_IP;
		printk(KERN_INFO "Parsed IP is: %d %d %d %d\n", octals[0], octals[1], octals[2], octals[3]);		
		ip = end_of_ip + 1;
		if (ip > end_of_input) {
			break; // check for pointer overrun
		}
	}	

	goto ok;

err:
	printk(KERN_INFO "message did not parse correctly...\n");
	goto end;
ok:	
	printk(KERN_INFO "message parsed correctly!\n");
end:
	return count;
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
