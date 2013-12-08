#ifndef _NIDHASH_H_
#define _NIDHASH_H_

#include <linux/uidgid.h>
#include <uapi/linux/ip.h>

typedef enum {
	NG_WHITELIST,
	NG_BLACKLIST
} ngmode_t;

struct _nidkey {
	uid_t uid;
	gid_t nid;
};

struct _nidpolicy {
	ngmode_t mode;  /* 0=blacklist, 1=whitelist */
	int size;
	struct _ip_list *ips;
};

struct _ip_list {
	__be32 addr;
	struct _ip_list *next;
};

struct _list {
	struct _nidkey *key;
	struct _nidpolicy *val;

	struct _list *next;
};

struct _hashtable {
	int size;
	struct _list **table;
};

int key_eq(struct _nidkey *a, struct _nidkey *b);

/* Allocate the hash table by size */
struct _hashtable *init_hash_table(int size);

/* Get index into table from key */
__u32 hash(struct _nidkey *key, struct _hashtable *hashtable);

/* Get policy by key */
struct _list *get(struct _hashtable *hashtable, uid_t uid, gid_t nid);

/* Add mapping: (nid, ip) --> policy */
int put(struct _hashtable *hashtable, uid_t uid, gid_t nid, ngmode_t mode);

/* Cleanup hash table and all of its lists */
void free(struct _hashtable *hashtable);

/* Determine if a policy has an explicit rule for an ip */
int policy_contains_ip(struct _nidpolicy *policy, __be32 addr);

int add_ip_to_policy(struct _nidpolicy *policy, __be32 addr);

#endif  /* NIDHASH_H_ */

