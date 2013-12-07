#include <linux/slab.h>
#include <linux/uidgid.h>
#include <uapi/linux/ip.h>

#include "nidhash.h"

struct _hashtable *init_hash_table(int size) {
	int i;
	struct _hashtable *hashtable;

	if (size < 1)
		return NULL;
	
	hashtable = kmalloc(sizeof(struct _hashtable), GFP_KERNEL);
	if (!hashtable)
		return NULL;
	
	hashtable->table = kmalloc(sizeof(struct _list) * size, GFP_KERNEL);
	if (!hashtable->table) {
		kfree(hashtable);
		return NULL;
	}

	hashtable->size = size;
	for (i = 0; i < size; i++)
		hashtable->table[i] = NULL;
		
	return hashtable;
}

void free(struct _hashtable *hashtable) {
	int i;
	struct _list *list, *temp;

	if (!hashtable)
		return;
	
	for (i = 0; i < hashtable->size; i++) {
		list = hashtable->table[i];
		while (list != NULL) {
			temp = list;
			list = list->next;
			kfree(temp->key);
			kfree(temp->val);
			kfree(temp);
		}
	}

	kfree(hashtable->table);
	kfree(hashtable);
}

/*
 * HASH: (uid, nid) --> u32
 * Could do better here. Good enough for now?
 */
__u32 hash(struct _nidkey *key, struct _hashtable *hashtable) {
	__u32 hashvalue;
	hashvalue = (__u32)key->nid * (__u32)key->uid;
	return hashvalue % hashtable->size;
}

int key_eq(struct _nidkey *a, struct _nidkey *b) {
	return (((__u32)a->nid == (__u32)b->nid) &&
	        ((__u32)a->uid == (__u32)b->uid));
}

struct _list *get(struct _hashtable *hashtable, uid_t uid, gid_t nid) {
	struct _list *list;
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

int put(struct _hashtable *hashtable, uid_t uid, gid_t nid, int blocked) {
	struct _nidkey *key;
	struct _nidpolicy *val;
	struct _list *new_list;
	struct _list *current_list;
	__u32 hashval;

	if (!hashtable)
		return -1;

	/* Prepare structures */
	key = kmalloc(sizeof(struct _nidkey), GFP_KERNEL);
	if (!key)
		return -1;
	key->uid = uid;
	key->nid = nid;

	val = kmalloc(sizeof(struct _nidpolicy), GFP_KERNEL);
	if (!val) {
		kfree(key);	
		return -1;
	}
	val->blocked = blocked;
	/* Add IPs to val policy */

	hashval = hash(key, hashtable);	
	new_list = kmalloc(sizeof(struct _list), GFP_KERNEL);
	if (!new_list) {
		kfree(key);
		kfree(val);
		return -1;
	}

	current_list = get(hashtable, uid, nid);
	if (current_list != NULL) {
		kfree(key);
		kfree(val);
		kfree(new_list);
		return 2;  /* already exists */
	}
	new_list->key = key;
	new_list->val = val;
	new_list->next = hashtable->table[hashval];
	hashtable->table[hashval] = new_list;

	return 0;
}
