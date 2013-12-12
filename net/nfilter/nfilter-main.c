#include "ngpolicy.h"

#include <linux/preempt_mask.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/ip.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/spinlock.h>
#include <net/tcp.h>

#include <net/sock.h>
#include <linux/socket.h>
#include <linux/fs.h>

#define POLICY_TABLE_SIZE 1021

static struct nf_hook_ops p;
DEFINE_SPINLOCK(irqlk);
long flags;

int blockpkt(uid_t uid, gid_t nid, __be32 addr)
{
	int print_debug;
	struct _list *policy;
	int block;

	read_lock(&ngpolicymap_rwlk);
	policy = get_ngpolicy(uid, nid);
	if (!policy) {
		read_unlock(&ngpolicymap_rwlk);
		return false;
	}

	switch(policy->val->mode) {
	case NG_WHITELIST:
		printk("Whitelist\n");
		if (ngpolicy_contains_ip(policy->val, addr))
			block = false;
		else
			block = true;
		break;
	case NG_BLACKLIST:
		printk("Blacklist\n");
		if (ngpolicy_contains_ip(policy->val, addr))
			block = true;
		else
			block = false;
		break;
	default:
		block = false;  /* do not block */
		break;
	}
	printk("block = %d\n", block);
	read_unlock(&ngpolicymap_rwlk);
	return block;
}

unsigned int hook_function(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	int i;
	struct cred *cc = current_cred();

	struct iphdr * ip_header = (struct iphdr *) skb_network_header(skb);
	struct user_namespace *user_ns = current_user_ns();

	__be32 daddr = ip_header->daddr;
	struct pid * pid = current->pid;
	uid_t uid = from_kuid_munged(user_ns, current_uid());

	// hack
	if (!uid) {
		// TODO: Come back to this
		if (! skb->sk || skb->sk->sk_state == TCP_TIME_WAIT) {
			printk(KERN_INFO "Was null pointer!!!\n");
			return NF_DROP;
		}
		if (skb->sk->sk_socket && skb->sk->sk_socket->file) {
			const struct cred *cred = skb->sk->sk_socket->file->f_cred;
			uid = cred->fsuid.val;
			cc = skb->sk->sk_socket->file->f_cred;
		} else {
			// We have no idea what is happening here, abort mission.
			printk(KERN_INFO "Caught the derefence fail! Dropping\n");
			return NF_DROP;
		}
	}

	/* For each nid, check policy of daddr */
	struct group_info *netgroup_info = get_group_info(cc->netgroup_info);
	for (i = 0; i < netgroup_info->ngroups; i++) {
		kgid_t knid = GROUP_AT(netgroup_info, i);
		gid_t nid = from_kgid_munged(user_ns, knid);
		printk("Checking policy for nid %d\n", nid);

		if (blockpkt(uid, nid, daddr))
		{
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

int nfilter_init(void)
{
	int retput;
	/*struct _list *policy;
	__be32 mitaddr, fbaddr; */

	printk(KERN_INFO "Loaded nfilter module\n");

	p.hook = hook_function;
	p.hooknum = NF_INET_LOCAL_OUT;
	p.pf = PF_INET;
	p.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&p);

	/* Initialize the policymap */
	rwlock_init(&ngpolicymap_rwlk);
	write_lock(&ngpolicymap_rwlk);
	retput = init_ngpolicymap(POLICY_TABLE_SIZE);

	/* Some test policies */
	/*
	mitaddr = make_ipaddr(18, 9, 22, 69);
	fbaddr = make_ipaddr(173, 252, 110, 27);

	retput = put_ngpolicy(1000, 42, NG_BLACKLIST);
	policy = get_ngpolicy(1000, 42);
	retput = add_ip_to_ngpolicy(policy->val, fbaddr);

	retput = put_ngpolicy(1000, 43, NG_WHITELIST);
	policy = get_ngpolicy(1000, 43);
	retput = add_ip_to_ngpolicy(policy->val, mitaddr);
	*/
	write_unlock(&ngpolicymap_rwlk);

	return 0;
}

void nfilter_exit(void)
{
	nf_unregister_hook(&p);
	write_lock(&ngpolicymap_rwlk);
	free_ngpolicymap();
	write_unlock(&ngpolicymap_rwlk);
	printk(KERN_INFO "Removed nfilter module\n");
}
