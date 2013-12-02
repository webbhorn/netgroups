#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/ip.h>

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

#define FACEBOOK_ADDR 460258477
static struct nf_hook_ops p;

/* a simple bsearch */
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

	return 0;
}

static void nfilter_exit(void)
{
	nf_unregister_hook(&p);

	printk(KERN_INFO "Removed nfilter module\n");
}

module_init(nfilter_init);
module_exit(nfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tim Donegan");
MODULE_DESCRIPTION("Filtering packets");
