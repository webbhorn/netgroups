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

// Writing to this file adds a policy
static ssize_t sysfile_add_to_kfifo(struct device* dev, struct device_attribute* attr,
	const char* buf, size_t count) {	
	// STRING CONSTANTS...refactor these into a .h file sometime soon
	const char * set_prefix = "set";
	const char * mode_blacklist = "b";
	const char * mode_whitelist = "w";
	
	int policy_mode = 0;	/* 0 is unset, 1 is blacklist, 2 whitelist */	

	char *uid; // Pointer to UID string
	char *nid; // Pointer to NID string
	char *mode; // Pointer to policy mode string
	uid_t uid_val; // UID as UID type
	gid_t nid_val; // NID as GID type
	
	__be32 ip_addrs[MAX_IPs]; // Store IP addresses
	__u8 octals[4]; // Store IP octals

	char *ip; // Pointer to IP address string
	char *end_of_input = buf + count; // End of input string
	char *end_of_ip; // End of IP address string
	char *octal_start; // Start of IP octal
	char *end_of_octal; // End of IP octal
	__u8 octal_val; // Octal as __u8 type
	__be32 parsed_IP; // Parsed IP as IP type

	int ip_i; // IP address loop var
	int octal_i; // Octal loop var

	if ( strnicmp(buf, set_prefix, strlen(set_prefix)) != 0 ) { // check set prefix
		printk("Invalid action specified. Valid actions are 'set' or 'get'.\n");
		goto err;
	}	
	
	uid = strchr(buf, ' '); // get UID
	if (!uid) {
		printk(KERN_INFO "Syntax error: could not find a UID.\n");
		goto err;
	}
	*uid = '\0';
	uid++;
	
	nid = strchr(uid, ' '); // get NID
	if (!nid) {
		printk(KERN_INFO "Syntax error: could not find an NID.\n");
		goto err;
	}
	*nid = '\0';
	nid++;

	mode = strchr(nid, ' '); // get policy mode
	if (!mode) {
		printk(KERN_INFO "Syntax error: could not find a policy mode.\n");
		goto err;
	}
	*mode = '\0';
	mode++;

	// Parse UID
	if (kstrtouint(uid, 10, &uid_val) != 0) { // depends on uid_t being unsigned int
		printk(KERN_INFO "Invalid UID specified.\n");
		goto err;
	}
	printk(KERN_INFO "uid is: %u\n", uid_val);
	
	// Parse NID
	if (kstrtouint(nid, 10, &nid_val) != 0) {
		printk(KERN_INFO "Invalid NID specified.\n");
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
		printk(KERN_INFO "Invalid policy mode specified.\n");
		goto err;
	}
	printk(KERN_INFO "Policy mode is: %d\n", policy_mode);

	// Parse IP addresses and save them	
	// need octals to be unsigned ints (specifically __u8's)
	ip = mode; // beginning of IP address list

	for (ip_i=0; ; ip_i++) {
		end_of_ip = strchr(ip, ' '); // Split IP by space
		if (end_of_ip) { // null terminate to allow strchr, etc. to work on intermediate strings
			*end_of_ip = '\0';	
		} else { // we're at the end of our input string
			end_of_ip = end_of_input;
		}

		// Split IP address into octals
		octal_start = ip;

		for (octal_i=0; octal_i<4; octal_i++) {
			end_of_octal = strchr(octal_start, '.');
			if (!end_of_octal) {
				if (octal_i != 3) { // No "." separator
					printk(KERN_INFO "Syntax error: IP octal not found.\n");
					goto err;
				}
				end_of_octal = end_of_ip; // Last octal has no "." separator
			} else {
				*end_of_octal = '\0'; // null terminate to use kstrtouint
			}

			// todo (jugonz97): convert to __u8 in standards-compliant way
			if (kstrtouint(octal_start, 10, &octal_val) != 0) {
				printk(KERN_INFO "Invalid IP octal.\n");
				goto err;
			}

			octals[octal_i] = octal_val; // store to be later converted into an IP
			octal_start = end_of_octal + 1;
		}
	
		// Make IP address type from octals	
		parsed_IP = make_ipaddr(octals[0], octals[1], octals[2], octals[3]);
		ip_addrs[ip_i] = parsed_IP;
		printk(KERN_INFO "Parsed IP is: %d %d %d %d\n", octals[0], octals[1], octals[2], octals[3]);		

		ip = end_of_ip + 1; // Parse next IP...
		if (ip > end_of_input) {
			break; // check for pointer overrun
		}
	}	

	goto ok;

err:
	printk(KERN_INFO "Set policy message unsuccessfully parsed.\n");
	goto end;
ok:	
	printk(KERN_INFO "Set policy message successfully parsed.\n");
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
