#include "nidhash.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/ip.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

#define HASH_TABLE_SIZE 1021
static struct _hashtable *policymap;

static struct nf_hook_ops p;

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

unsigned int hook_function(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	int i;

	struct iphdr * ip_header = (struct iphdr *) skb_network_header(skb);
	struct user_namespace *user_ns = current_user_ns();

	__be32 daddr = ip_header->daddr;
	kuid_t kuid = current_uid();
	uid_t uid = from_kuid_munged(user_ns, kuid);

	/* For each nid, check policy of daddr */
	const struct cred *cc = current_cred();
	struct group_info *netgroup_info = get_group_info(cc->netgroup_info);
	for (i = 0; i < netgroup_info->ngroups; i++) {
		struct _list *policy;
		kgid_t knid = GROUP_AT(netgroup_info, i);
		gid_t nid = from_kgid_munged(user_ns, knid);
		policy = get(policymap, uid, nid, daddr);

		if (policy == NULL)
			continue;
		if (policy->val->blocked)
			return NF_DROP;
	}

	return NF_ACCEPT;
}

static int nfilter_init(void)
{
	int retput;
	__be32 mitaddr, fbaddr;

	printk(KERN_INFO "Loaded nfilter module\n");

	p.hook = hook_function;
	p.hooknum = NF_INET_LOCAL_OUT;
	p.pf = PF_INET;
	p.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&p);

	/* Initialize the policymap */
	policymap = init_hash_table(HASH_TABLE_SIZE);

	/* Some test policies */
	mitaddr = make_ipaddr(18, 9, 22, 69);
	fbaddr = make_ipaddr(173, 252, 110, 27);
	retput = put(policymap, 1000, 43, mitaddr, true);
	retput = put(policymap, 1000, 42, fbaddr, true);

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
MODULE_AUTHOR("Tim Donegan <donegan@mit.edu>, Webb Horn <webbhorn@mit.edu>");
MODULE_DESCRIPTION("Netgroups filtering code");
