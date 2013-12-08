#include <linux/slab.h>
#include <linux/uidgid.h>
#include <uapi/linux/ip.h>

#include "ngpolicy.h"

static struct _hashtable *ngpolicymap;

rwlock_t ngpolicymap_rwlk; 

EXPORT_SYMBOL(ngpolicymap_rwlk);

static void free_ip_list(struct _ip_list *list) {
	struct _ip_list *temp;
	while (list != NULL) {
		temp = list;
		list = list->next;
		kfree(temp);
	}
}

static void free_nidpolicy(struct _nidpolicy *policy) {
	if (!policy)
		return;
	free_ip_list(policy->ips);
	kfree(policy);
}

/*
 * HASH: (uid, nid) --> u32
 * Could do better here. Good enough for now?
 */
static __u32 hash(struct _nidkey *key, struct _hashtable *hashtable) {
	__u32 hashvalue;
	hashvalue = (__u32)key->nid * (__u32)key->uid;
	return hashvalue % hashtable->size;
}

static int key_eq(struct _nidkey *a, struct _nidkey *b) {
	return (((__u32)a->nid == (__u32)b->nid) &&
	        ((__u32)a->uid == (__u32)b->uid));
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

EXPORT_SYMBOL(make_ipaddr);

/*
 * Allocate and initialize the netgroups policy table.
 *
 * Caller is responsible for acquiring and releasing write lock on
 * ngpolicymap_rwlk during use.
 *
 * Returns:
 *	NG_SUCCESS on successful init.
 *	NG_ERRARG if size < 1.
 *	NG_ERRMAP if the map is already allocated or there is a problem in the
 *		data structure.
 */
int init_ngpolicymap(int size) {
	int i;
	if (size < 1)
		return NG_ERRARG;
	
	ngpolicymap = kmalloc(sizeof(struct _hashtable), GFP_KERNEL);
	if (!ngpolicymap)
		return NG_ERRMAP;
	
	ngpolicymap->table = kmalloc(sizeof(struct _list) * size, GFP_KERNEL);
	if (!ngpolicymap->table) {
		kfree(ngpolicymap);
		return NG_ERRMAP;
	}

	ngpolicymap->size = size;
	for (i = 0; i < size; i++)
		ngpolicymap->table[i] = NULL;
		
	return NG_SUCCESS;
}

EXPORT_SYMBOL(init_ngpolicymap);

/*
 * Free all of the memory used to store policies, including all of the
 * recursive structures.
 *
 * Caller is responsible for acquiring and releasing write lock on
 * ngpolicymap_rwlk during use.
 */
void free_ngpolicymap() {
	int i;
	struct _list *list, *temp;
	struct _hashtable *hashtable;

	hashtable = ngpolicymap;
	if (!hashtable)
		return;
	
	for (i = 0; i < hashtable->size; i++) {
		list = hashtable->table[i];
		while (list != NULL) {
			temp = list;
			list = list->next;
			kfree(temp->key);
			free_nidpolicy(temp->val);
			kfree(temp);
		}
	}

	kfree(hashtable->table);
	kfree(hashtable);
}

EXPORT_SYMBOL(free_ngpolicymap);

/*
 * Look up netgroups policy for (uid, nid) tuple.
 *
 * Caller is responsible for acquiring and releasing read lock on
 * ngpolicymap_rwlk during use.
 *
 * Returns:
 *	Pointer to a struct _list if item is found.
 *	NULL if policy does not exist.
 */
struct _list *get_ngpolicy(uid_t uid, gid_t nid) {
	struct _list *list;
	struct _hashtable *hashtable = ngpolicymap;
	struct _nidkey key = {
		.uid = uid,
		.nid = nid
	};

	__u32 hashval = hash(&key, hashtable);
	for (list = hashtable->table[hashval]; list != NULL; list = list->next)
		if (key_eq(&key, list->key))
			return list;

	return NULL;
}

EXPORT_SYMBOL(get_ngpolicy);

/*
 * Create a new netgroups policy for a (uid, nid) tuple under the specified
 * mode (whitelist or blacklist).
 *
 * Caller is responsible for acquiring and releasing write lock on
 * ngpolicymap_rwlk during use.
 *
 * Returns:
 *	NG_SUCCESS if policy is successfully added.
 *	NG_EXISTS if there is already a policy in table for (uid, nid).
 *	NG_ERRMAP if the policy table is unitialized or has a problem.
 *	NG_NOMEM if memory allocation of new policy failed.
 */
int put_ngpolicy(uid_t uid, gid_t nid, ngmode_t mode) {
	struct _hashtable *hashtable;
	struct _nidkey *key;
	struct _nidpolicy *val;
	struct _list *new_list;
	struct _list *current_list;
	__u32 hashval;

	hashtable = ngpolicymap;
	if (!hashtable)
		return NG_ERRMAP;

	/* Prepare structures */
	key = kmalloc(sizeof(struct _nidkey), GFP_KERNEL);
	if (!key)
		return NG_NOMEM;
	key->uid = uid;
	key->nid = nid;

	val = kmalloc(sizeof(struct _nidpolicy), GFP_KERNEL);
	if (!val) {
		kfree(key);	
		return NG_NOMEM;
	}
	val->mode = mode;
	val->ips = NULL;

	hashval = hash(key, hashtable);	
	new_list = kmalloc(sizeof(struct _list), GFP_KERNEL);
	if (!new_list) {
		kfree(key);
		kfree(val);
		return NG_NOMEM;
	}

	current_list = get_ngpolicy(uid, nid);
	if (current_list != NULL) {
		kfree(key);
		kfree(val);
		kfree(new_list);
		return NG_EXISTS;  /* policy for (uid, nid) already exists */
	}
	new_list->key = key;
	new_list->val = val;
	new_list->next = hashtable->table[hashval];
	hashtable->table[hashval] = new_list;

	return NG_SUCCESS;
}

EXPORT_SYMBOL(put_ngpolicy);

/*
 * Extend an existing policy to include another ip address.
 *
 * Caller is responsible for acquiring and releasing write lock on
 * ngpolicymap_rwlk during use.
 *
 * Returns:
 *	NG_SUCCESS if ip was successfully added.
 *	NG_ERRARG if the provided policy is invalid.
 *	NG_NOMEM if memory allocation of new ip failed.
 */
int add_ip_to_ngpolicy(struct _nidpolicy *policy, __be32 addr) {
	struct _ip_list *head;
	struct _ip_list *new;

	if (!policy)
		return NG_ERRARG;
	head = policy->ips;

	new = kmalloc(sizeof(struct _ip_list), GFP_KERNEL);
	if (!new)
		return NG_NOMEM;
	new->addr = addr;
	new->next = head;

	policy->ips = new;
	policy->size += 1;
	return NG_SUCCESS;
}

EXPORT_SYMBOL(add_ip_to_ngpolicy);

/*
 * Determine if a netgroups policy has a rule for a particular ip address.
 *
 * Caller is responsible for acquiring and releasing read lock on
 * ngpolicymap_rwlk during use.
 */
int ngpolicy_contains_ip(struct _nidpolicy *policy, __be32 addr) {
	struct _ip_list *list;
	for (list = policy->ips; list != NULL; list = list->next)
		if (list->addr == addr)
			return true;
	return false;
}

EXPORT_SYMBOL(ngpolicy_contains_ip);
