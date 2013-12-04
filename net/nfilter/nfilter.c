#include "nidhash.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/ip.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

#define HASH_TABLE_SIZE 8
static struct _hashtable *policymap;

#define FACEBOOK_ADDR 460258477
static struct nf_hook_ops p;

/*
 * a simple bsearch
 * TODO: export group_search from groups.c.
 */
int groups_search(const struct group_info *group_info, kgid_t grp)
{
	unsigned int left, right;

	if (!group_info)
		return 0;

	left = 0;
	right = group_info->ngroups;
	while (left < right) {
		unsigned int mid = (left+right)/2;
		if (gid_gt(grp, GROUP_AT(group_info, mid)))
			left = mid + 1;
		else if (gid_lt(grp, GROUP_AT(group_info, mid)))
			right = mid;
		else
			return 1;
	}
	return 0;
}



unsigned int hook_function(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{

	struct iphdr * ip_header = (struct iphdr *) skb_network_header(skb);
	__be32 daddr = ip_header->daddr;

	// Test: Block if process does not have NID 42
	const struct cred *cc = current_cred();
	struct group_info *netgroup_info = get_group_info(cc->netgroup_info);
	struct user_namespace *user_ns = current_user_ns();
	kgid_t nid = make_kgid(user_ns, (gid_t) 42);
	if (groups_search(netgroup_info, nid))
		printk(KERN_INFO "Caller is NID 42.\n");
	put_group_info(netgroup_info);

	/*
	 * For each nid in calling process:
	 *	- Check if destination IP is blocked by a policy.
	 *		- YES: drop packet
	 *		- NO: permit packet
	 *
	 * Need a fast lookup function:
	 *	f(nid, ip_addr) --> blocked? (boolean)
	 *
	 * Should support:
	 *	set(nid, ip_addr, block/permit)
	 *	get(nid, ip_addr) --> block/permit
	 *
	 * This is: a map from (nid, ip_addr) --> boolean
	 */

	// Drop all facebook packets
	if (daddr == FACEBOOK_ADDR)
		return NF_DROP;

	return NF_ACCEPT;
}

static int nfilter_init(void)
{
	printk(KERN_INFO "Loaded nfilter module\n");

	p.hook = hook_function;
	p.hooknum = NF_INET_LOCAL_OUT;
	p.pf = PF_INET;
	p.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&p);

	/* Initialize the policymap */
	policymap = init_hash_table(HASH_TABLE_SIZE);

	return 0;
}

static void nfilter_exit(void)
{
	nf_unregister_hook(&p);

	free(policymap);

	printk(KERN_INFO "Removed nfilter module\n");
}

module_init(nfilter_init);
module_exit(nfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tim Donegan");
MODULE_DESCRIPTION("Filtering packets");



/*
 * hash table stuff
 */

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

/* Could do better here. Good enough for now? */
__u32 hash(struct _nidkey *key, struct _hashtable *hashtable) {
	__u32 hashvalue;
	hashvalue = (__u32)key->nid * (__u32)key->ip_addr;
	return hashvalue % hashtable->size;
}

int key_eq(struct _nidkey *a, struct _nidkey *b) {
	return (((__u32)a->nid == (__u32)b->nid) && 
	        ((__u32)a->ip_addr == (__u32)b->ip_addr));
}

struct _list *get(struct _hashtable *hashtable, gid_t nid, __be32 ip_addr) {
	struct _list *list;
	struct _nidkey key = {
		.nid = nid,
		.ip_addr = ip_addr,
	};

	__u32 hashval = hash(&key, hashtable);
	for (list = hashtable->table[hashval]; list != NULL; list = list->next) {
		if (key_eq(&key, list->key))
			return list;
	}

	return NULL;
}

int put(struct _hashtable *table, gid_t nid, __be32 ip_addr, int blocked) {
	struct _nidkey *key;
	struct _nidpoilcy *val;
	struct _list *new_list;
	struct _list *current_list;
	__u32 hashval;

	if (!hashtable)
		return -1;

	/* Prepare structures */
	key = kmalloc(sizeof(struct _nidkey), GFP_KERNEL);
	if (!key)
		return -1;
	key->nid = nid;
	key->ip_addr = ip_addr;

	val = kmalloc(sizeof(struct _nidpolicy), GFP_KERNEL);
	if (!val) {
		kfree(key);	
		return -1;
	}
	val->blocked = blocked;

	hashval = hash(&key, hashtable);	
	new_list = kmalloc(sizeof(struct _list), GFP_KERNEL);
	if (!new_list) {
		kfree(key);
		kfree(val);
		return -1;
	}

	current_list = get(hashtable, nid, ip_addr);
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

