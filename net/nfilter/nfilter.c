#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/ip.h>

#define FACEBOOK_ADDR 460258477
static struct nf_hook_ops p;

unsigned int hook_function(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{

	struct iphdr * ip_header = (struct iphdr *) skb_network_header(skb);
	__be32 daddr = ip_header->daddr;

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
