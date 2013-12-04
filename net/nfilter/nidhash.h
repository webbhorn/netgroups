#ifndef _NIDHASH_H_
#define _NIDHASH_H_

#include <linux/uidgid.h>
#include <uapi/linux/ip.h>

struct _nidkey {
	gid_t nid;
	__be32 ip_addr;
};

struct _nidpolicy {
	int blocked;
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
struct _list *get(struct _hashtable *hashtable, gid_t nid, __be32 ip_addr);

/* Add mapping: (nid, ip) --> policy */
int put(struct _hashtable *hashtable, gid_t nid, __be32 ip_addr, int blocked);

/* Cleanup hash table and all of its lists */
void free(struct _hashtable *hashtable);

#endif  /* NIDHASH_H_ */

