/* Policy setter/getter for nfilter */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <uapi/linux/ip.h>
#include <asm/uaccess.h>

#include "ngpolicy.h"
#include "policy_sysfile.h"

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

// Reading this file shows all policies for the given UIDs/GIDs
static ssize_t sysfile_read_policies(struct device* dev, struct device_attribute* attr,
	char* buf) {
	char noOutputMsg[] = "No policies for current UID and NIDs\n";
	char toOutput[512];

	// get uid from user_namespace
	struct user_namespace *user_ns = current_user_ns();
	kuid_t kuid = current_uid();
	uid_t uid = from_kuid_munged(user_ns, kuid);

// get nid's
	const struct cred *cc = current_cred();
	struct group_info *ng_info = get_group_info(cc->netgroup_info);
	gid_t nids[MAX_NIDs]; // look at max of 16 nid's of this user
	int num_nids; // actual number of stored nid's

	struct _list *policy; // policy retrieved from hashtable
	struct _nidpolicy *current_policy; // ...as _nidpolicy item
	struct _nidkey *current_policy_key;
	struct _ip_list *current_policy_ips;
	__u8 ip_octals[4];

	int policy_ip_i; // index for IP list traversal
	int nid_i; // index for nid acquisition/iteration
	kgid_t knid; // group for nid_i

	// Get all NID's	
	for (nid_i = 0; nid_i < ng_info->ngroups && nid_i < MAX_NIDs; nid_i++) {
		knid = GROUP_AT(ng_info, nid_i);
		nids[nid_i] = from_kgid_munged(user_ns, knid);
	}
	num_nids = nid_i;

	if (num_nids == 0) {
		return snprintf(buf, sizeof noOutputMsg, noOutputMsg); // nothing to print
	} else {
		sprintf(toOutput, "Existing policies:\n"); // Add header text
	}

	read_lock(&ngpolicymap_rwlk); // Get read lock for policy map
	// Get all policies for given user and existing NIDs and print them.
	for (nid_i = 0; nid_i < num_nids; nid_i++) {
		policy = get_ngpolicy(uid, nids[nid_i]); // Get policy
		if (!policy) { // check for no existing policies
			read_unlock(&ngpolicymap_rwlk); // about to return an error, unlock
			return snprintf(buf, sizeof noOutputMsg, noOutputMsg);
		}
		
		// We have a policy: parse it
		current_policy = policy->val;
		current_policy_key = policy->key;

		// Check policy for soundness
		if (!current_policy) {
			printk(KERN_INFO "Error: policy item in list was null...\n");
			break;
		} else if (current_policy_key->uid != uid || current_policy_key->nid != nids[nid_i]) {
			printk(KERN_INFO "Bad key in returned list\n");
		} else {
			snprintf(toOutput, sizeof toOutput, "%sFound policy for nid %d:", toOutput, (int)nids[nid_i]);

			// Check policy mode
			if (current_policy->mode == NG_WHITELIST) {
				snprintf(toOutput, sizeof toOutput, "%s Mode: whitelist", toOutput);
			} else if (current_policy->mode == NG_BLACKLIST) {
				snprintf(toOutput, sizeof toOutput, "%s Mode: blacklist", toOutput);
			} else {
				snprintf(toOutput, sizeof toOutput, "%s Mode: unknown mode", toOutput);
			}
			snprintf(toOutput, sizeof toOutput, "%s With IPs:", toOutput);

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
		snprintf(toOutput, sizeof toOutput, "%s\n", toOutput); // add newline for next policy
		
	}

	read_unlock(&ngpolicymap_rwlk); // unlock read lock!!
	return snprintf(buf, PAGE_SIZE, "%s", toOutput); // Print to provided buffer
}

// Writing to this file adds a policy
static ssize_t sysfile_set_policy(struct device* dev, struct device_attribute* attr,
	const char* buf, size_t count) {	

	ngmode_t policy_mode;	// Policy type: see ngpolicy.h
	char *nid; // Pointer to NID string
	char *mode; // Pointer to policy mode string

	struct user_namespace *user_ns = current_user_ns();
	kuid_t kuid = current_uid();
	uid_t uid_val = from_kuid_munged(user_ns, kuid); // UID as UID type
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
	
	nid = strchr(buf, ' '); // get NID
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

	// Parse NID
	if (kstrtouint(nid, 10, &nid_val) != 0) { // Depends on gid_t being unsigned int
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
		write_unlock(&ngpolicymap_rwlk); // unlock write lock	
		goto err;
	}
	// Now, get the policy just inserted
	matching_policy = get_ngpolicy(uid_val, nid_val);
	do {
		if (!matching_policy) { // check for NULL policy
			printk("Inserted policy could not be referenced!\n");
			write_unlock(&ngpolicymap_rwlk); // unlock write lock
			goto err;
		}
		
		mp_key = matching_policy->key;	
		if ((mp_key->uid == uid_val) && (mp_key->nid == nid_val)) {
			inserted_policy = matching_policy->val; // found our policy
			break;
		} else {
			printk(KERN_INFO "Saw policy that did not match our uid/nid\n");
			matching_policy = matching_policy->next;
		}
	} while (true);

	// Now, have policy. Add IP's to it
	for (ng_policy_i = 0; ng_policy_i <= ip_i; ng_policy_i++) {
		if (add_ip_to_ngpolicy(inserted_policy, ip_addrs[ng_policy_i]) != 0) {
			printk(KERN_INFO "Addding an IP to a policy failed.\n");
		}
		printk(KERN_INFO "Added ip to policy.\n");
	
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
static DEVICE_ATTR(nid_policies, 0666, sysfile_read_policies, sysfile_set_policy);

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

	// Now, create a device for sysfs to operate on
	sysfs_device = device_create(device_class, NULL, device_nums, NULL, PROG_NAME);
	if (sysfs_device == NULL) {
		return_val = -1;
		goto err_dev_create;
	}	

	// Add files in /sys for adding and resetting the queue
	return_val = device_create_file(sysfs_device, &dev_attr_nid_policies);
	if (return_val < 0) {
		printk(KERN_INFO "%s failed to create sysfs file...\n", PROG_NAME);
		goto err_create_file;
	}

	printk(KERN_INFO "%s finished initialization\n", PROG_NAME);
	return 0; // setup OK, else, destroy everything created

err_create_file:
	device_destroy(device_class, device_nums);
err_dev_create:
	class_destroy(device_class);
err_class_create:
	unregister_chrdev_region(device_nums, 1);
err:	
	printk(KERN_INFO "%s failed to finish initialization\n", PROG_NAME);
	return return_val;	
}

// Called on unload of kernel module
void policy_set_cleanup(void) {
	device_remove_file(sysfs_device, &dev_attr_nid_policies);	
	device_destroy(device_class, device_nums);
	class_destroy(device_class);
	unregister_chrdev_region(device_nums, 1);
	printk(KERN_INFO "%s has cleaned up and exited\n", PROG_NAME);
}

