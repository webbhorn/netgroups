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
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <uapi/linux/ip.h>
#include <asm/uaccess.h>

#include "ngpolicy.h"
#include "set_policy.h"

// String constants
const char * set_prefix = "set";
const char * mode_blacklist = "b";
const char * mode_whitelist = "w";	

// Helper function to get an array of __u8's from an IP.
void get_ip_octals(__be32 ip_addr, __u8 *toPut) {
	__u8 octal;
        int i;

        for (i=3; i>=0; i--) {
                octal = ip_addr & 0xFF; // get low 8 bits as __u8
                toPut[i] = octal;
                ip_addr = ip_addr >> 8;
        }
}

// /dev read function. On read, prints out policies for given UID/NID.
static ssize_t read_dev(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
	char noOutputMsg[] = "No policies for current UID and NID 777\n";
	char toOutput[512];

	// get uid from user_namespace
	struct user_namespace *user_ns = current_user_ns();
	kuid_t kuid = current_uid();
	uid_t uid = from_kuid_munged(user_ns, kuid);
	gid_t nid = 777;

	struct _list *policies;
	struct _nidpolicy *current_policy;
	struct _nidkey *current_policy_key;
	struct _ip_list *current_policy_ips;
	__u8 ip_octals[4];

	int policy_ip_i; // index for IP list traversal


	if (*f_pos > 0) {
		return 0; // Don't return anything on subsequent reads
	}

	// Get all policies for given user and print them.
	// Use user ID 1000 and fixed NID: 777 for now
	read_lock(&ngpolicymap_rwlk);	// Get read lock for policy map
	policies = get_ngpolicy(uid, nid); // Get policies
	if (!policies) { // check for no existing policies
		if (copy_to_user(buf, noOutputMsg, sizeof noOutputMsg) ) {
			return -EFAULT;
		}

		*f_pos = sizeof noOutputMsg;
		return sizeof noOutputMsg;
	}
	
	// We have a policy: parse it
	while (policies) {
		current_policy = policies->val;
		current_policy_key = policies->key;

		// Check policy for soundness
		if (!current_policy) {
			printk(KERN_INFO "Error: policy item in list was null...\n");
			break;
		} else if (current_policy_key->uid != uid || current_policy_key->nid != nid) {
			printk(KERN_INFO "Bad key in returned list\n");
		} else {
			snprintf(toOutput, sizeof toOutput, "%sFound policy: ", toOutput);

			// Check policy mode
			if (current_policy->mode == NG_WHITELIST) {
				snprintf(toOutput, sizeof toOutput, "%s whitelist: ", toOutput);
			} else if (current_policy->mode == NG_BLACKLIST) {
				snprintf(toOutput, sizeof toOutput, "%s blacklist: ", toOutput);
			} else {
				snprintf(toOutput, sizeof toOutput, "%s unknown mode: ", toOutput);
			}
			snprintf(toOutput, sizeof toOutput, "%s With IPs: ", toOutput);

			// Add all matching IP's to output string
			current_policy_ips = current_policy->ips;
			for (policy_ip_i = 0; policy_ip_i < current_policy->size; policy_ip_i++) {
				if (!current_policy_ips) {
					printk(KERN_INFO "Error: stated size of ip list was incorrect\n");
					break;
				}

				// Break IP into octals (for printing)
				get_ip_octals(current_policy_ips->addr, (__u8 *)(&ip_octals));
				snprintf(toOutput, sizeof toOutput, "%s %u.%u.%u.%u ", toOutput,
					ip_octals[3], ip_octals[2], ip_octals[1], ip_octals[0]);

				current_policy_ips = current_policy_ips->next; // Get next IP in policy
			}
		}
	
	        policies = policies->next; // Now, get the next policy
		snprintf(toOutput, sizeof toOutput, "%s\n", toOutput); // add newline for next policy
	}
	
	// Now, return the string to the user	
	read_unlock(&ngpolicymap_rwlk);
	if (count > strlen(toOutput)) {
		count = strlen(toOutput);
	}
	if (copy_to_user(buf, toOutput, count)) {
		return -EFAULT;
	}	

	*f_pos = count;
	return count;
}

static int open_dummy(struct inode *inode, struct file *filp) {	// Do not allow writes to /dev file
	if ( ((filp->f_flags & O_ACCMODE) == O_WRONLY) ||
		((filp->f_flags & O_ACCMODE) == O_RDWR) ) {
  		printk(KERN_INFO "Cannot write to this file!!!\n");
  		return -EACCES;
	}
	return 0;
}

static int release_dummy(struct inode *inode, struct file *filp) { return 0; }

// This defines how the file in /dev is arranged
static struct file_operations f_ops = {
	.open = open_dummy,
	.read = read_dev,
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
	const char *end_of_input = buf + count; // End of input string
	char *end_of_ip; // End of IP address string
	char *octal_start; // Start of IP octal
	char *end_of_octal; // End of IP octal
	__u8 octal_val; // Octal as __u8 type
	unsigned int octal_as_uint; // Octal as uint type;
	__be32 parsed_IP; // Parsed IP as IP type

	struct _list* matching_policy; // policy that comes from hashtable lookup
	struct _nidpolicy* inserted_policy; // actual inserted policy
	struct _nidkey *mp_key; // key of (uid, nid) from policy	

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
			end_of_ip = (char *)end_of_input;
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

			if (kstrtouint(octal_start, 10, &octal_as_uint) != 0) {
				printk(KERN_INFO "Invalid IP octal.\n");
				goto err;
			}
			
			octal_val = (__u8)octal_as_uint; // Convert to __u8
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
		
		mp_key = matching_policy->key;	
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
static DEVICE_ATTR(set_policy, 0222, NULL, sysfile_set_policy);

// Called on load of kernel module
int policy_set_init(void) {
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
void policy_set_cleanup(void) {
	cdev_del(policy_cdev);
	device_remove_file(sysfs_device, &dev_attr_set_policy);
	device_destroy(device_class, device_nums);
	class_destroy(device_class);
	unregister_chrdev_region(device_nums, 1);
	printk(KERN_INFO "%s has cleaned up and exited\n", PROG_NAME);
}

