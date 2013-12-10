#ifndef _SETPOLICY_H_
#define _SETPOLICY_H_

#include <linux/types.h>
#include <linux/device.h>
#include <linux/cdev.h>

#define PROG_NAME "set_policy"
#define CLASS_NAME "nfilter_policies"
#define MAX_IPs 64

// changeable names in the format of strings to parse
extern const char* set_prefix;
extern const char* mode_blacklist;
extern const char* mode_whitelist;

// Sysfs & dev file types
static dev_t device_nums;
struct device *sysfs_device;
static struct class *device_class;
static struct cdev *policy_cdev;

#endif /* _SETPOLICY_H_ */
