/* Set_Policy Kernel Module
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
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <uapi/linux/ip.h>
#include <asm/uaccess.h>

#include "../include/nfilter.h"
#include "../include/ngpolicy.h"
#include "set_policy.h"

// String constants
const char * set_prefix = "set";
const char * mode_blacklist = "b";
const char * mode_whitelist = "w";	

static ssize_t read_dummy(struct file *filp, char __user *buf,
		size_t count, loff_t *f_pos) {
	char tocopy[] = "Function not implemented\n";
	
	if (*f_pos > 0) {
		return 0; // Don't return anything on subsequent reads
	}
	
	// Tell user we don't do anything	
	if (copy_to_user(buf, tocopy, sizeof(tocopy)) ) {
		return -EFAULT;
	}

	return count;
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

// Writing to this file adds a policy
static ssize_t sysfile_set_policy(struct device* dev, struct device_attribute* attr,
	const char* buf, size_t count) {	

	ngmode_t policy_mode;	// Policy type: see ngpolicy.h
	char *uid; // Pointer to UID string
	char *nid; // Pointer to NID string
	char *mode; // Pointer to policy mode string
	uid_t uid_val; // UID as UID type
	gid_t nid_val; // NID as GID type

	__be32 ip_addrs[MAX_IPs]; // IP address array	
	__u8 octals[4]; // Store IP octals

	char *ip; // Pointer to IP address string
	char *end_of_input = buf + count; // End of input string
	char *end_of_ip; // End of IP address string
	char *octal_start; // Start of IP octal
	char *end_of_octal; // End of IP octal
	__u8 octal_val; // Octal as __u8 type
	__be32 parsed_IP; // Parsed IP as IP type

	struct _list* matching_policy; // policy that comes from hashtable lookup
	struct _nidpolicy* inserted_policy; // actual inserted policy
	
	int ip_i; // IP address loop var
	int octal_i; // Octal loop var
	int ng_policy_i; // ng_policy loop var
	int ng_policy_err; // Error code returned by put_ngpolicy

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
		policy_mode = NG_BLACKLIST;
		mode = mode + strlen(mode_blacklist) + 1;
	} else if (strnicmp(mode, mode_whitelist, strlen(mode_whitelist)) == 0) {
		policy_mode = NG_WHITELIST;
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
		ip_addrs[ip_i] = parsed_IP; // save in array
		printk(KERN_INFO "Parsed IP is: %d %d %d %d\n", octals[0], octals[1], octals[2], octals[3]);		

		ip = end_of_ip + 1; // Parse next IP...
		if (ip > end_of_input) {
			break; // check for pointer overrun
		}
	}	


	// Now, ip_addrs holds IP's...and ip_i holds the number of them
	write_lock(&ngpolicymap_rwlk);	// Get write_lock to put new policy
	ng_policy_err = put_ngpolicy(uid_val, nid_val, policy_mode);
	if (ng_policy_err != 0) {
		printk(KERN_INFO "put_ngpolicy returned: %d\n", ng_policy_err);
		goto err;
	}
	// Now, get the policy just inserted
	matching_policy = get_ngpolicy(uid_val, nid_val);
	do {
		if (!matching_policy) { // check for NULL policy
			printk("Inserted policy could not be referenced!\n");
			goto err;
		}
		
		struct _nidkey *mp_key = matching_policy->key;	
		if ((mp_key->uid == uid_val) && (mp_key->nid == nid_val)) {
			inserted_policy = matching_policy->val; // found our policy
			break;
		} else {
			matching_policy = matching_policy->next;
		}
	} while (true);

	// Now, have policy. Add IP's to it
	for (ng_policy_i = 0; ng_policy_i <= ip_i; ng_policy_i++) {
		printk(KERN_INFO "Added ip to policy.\n");
		if (add_ip_to_ngpolicy(inserted_policy, ip_addrs[ng_policy_i]) != 0) {
			printk(KERN_INFO "Addding an IP to a policy failed.\n");
		}
	}

	write_unlock(&ngpolicymap_rwlk); // Free read/write lock

	printk(KERN_INFO "Policy has been set!\n");
	goto ok;

err:
	printk(KERN_INFO "Set policy message unsuccessfully parsed.\n");
	goto end;
ok:	
	printk(KERN_INFO "Set policy message successfully parsed.\n");
end:
	return count;
}

// Declare the sysfs methods used
static DEVICE_ATTR(set_policy, S_IWUSR, NULL, sysfile_set_policy);

// Called on load of kernel module
static int __init policy_set_init(void) {
	int return_val;
	printk(KERN_INFO "%s has started to init\n", PROG_NAME);
	
	// Alloc the device numbers
	return_val = alloc_chrdev_region(&device_nums, 0, 1, PROG_NAME);
	if (return_val < 0) {
		goto err;
	}

	// Need to register the device in a class (virtual device here)	
	if ((device_class = class_create(THIS_MODULE, CLASS_NAME)) == NULL) {
		return_val = -1;
		goto err_class_create;
	}

	// Now, create a device file (in /dev)
	sysfs_device = device_create(device_class, NULL, device_nums, NULL, PROG_NAME);
	if (sysfs_device == NULL) {
		return_val = -1;
		goto err_dev_create;
	}	

	// Add files in /sys for adding and resetting the queue
	return_val = device_create_file(sysfs_device, &dev_attr_set_policy);
	if (return_val < 0) {
		printk(KERN_INFO "%s failed to create the set_policy sysfs file...\n", PROG_NAME);
	}

	// Need to register a character device
	// Do this by allocing/initing a cdev struct
	policy_cdev = cdev_alloc();
	cdev_init(policy_cdev, &f_ops);
	policy_cdev->owner = THIS_MODULE;

	// Add device to kernel
	return_val = cdev_add(policy_cdev, device_nums, 1);
	if (return_val < 0) {
		goto err_cdev_add;
	}

	// Finish setup
	return 0; // setup OK, else, destroy everything created

err_cdev_add:
	device_remove_file(sysfs_device, &dev_attr_set_policy);
	device_destroy(device_class, device_nums);
err_dev_create:
	class_destroy(device_class);
err_class_create:
	unregister_chrdev_region(device_nums, 1);
err:	
	printk(KERN_INFO "%s exited during initialization\n", PROG_NAME);
	return return_val;	
}

// Called on unload of kernel module
static void __exit policy_set_cleanup(void) {
	cdev_del(policy_cdev);
	device_remove_file(sysfs_device, &dev_attr_set_policy);
	device_destroy(device_class, device_nums);
	class_destroy(device_class);
	unregister_chrdev_region(device_nums, 1);
	printk(KERN_INFO "%s has cleaned up and exited\n", PROG_NAME);
}

module_init(policy_set_init);
module_exit(policy_set_cleanup);

// Module info
MODULE_AUTHOR("Julian Gonzalez");
MODULE_DESCRIPTION("Policy setter for NID/nfilter module");
MODULE_LICENSE("GPL");
