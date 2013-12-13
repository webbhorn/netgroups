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
		if (ngpolicy_contains_ip(policy->val, addr))
			block = false;
		else
			block = true;
		break;
	case NG_BLACKLIST:
		if (ngpolicy_contains_ip(policy->val, addr))
			block = true;
		else
			block = false;
		break;
	default:
		block = false;  /* do not block */
		break;
	}
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
	struct group_info *netgroup_info;
	const struct cred *cc = current_cred();

	struct iphdr * ip_header = (struct iphdr *) skb_network_header(skb);
	struct user_namespace *user_ns = current_user_ns();

	__be32 daddr = ip_header->daddr;
	uid_t uid = from_kuid_munged(user_ns, current_uid());

	/**
	 * One problem with using the netfilter API is that the hooks
	 * are not always executed in kernel context. Specifically,
	 * most protocols, such as UDP and ICMP, always execute in
	 * kernel context, but other protocols, such as TCP, do not have
	 * the same requirement. We have no easy way of getting the creds
	 * when in interrupt context, so this code block provides a hacky
	 * way of doing it. In a more well developed application, we would
	 * find a better (correct) way of getting the cred. The cred we get
	 * here is the cred associated with the socket, not the cred of the
	 * process writing to the socket -- for the purposed of the demo,
	 * they are the same.
	 */
	if (in_interrupt()) {
		if (! skb->sk || skb->sk->sk_state == TCP_TIME_WAIT ||
				! skb->sk->sk_socket || ! skb->sk->sk_socket->file) {
			// null pointer - an occasional dropped packet never hurt anyone :)
			return NF_DROP;
		} else {
			// get the alternate cred
			cc = skb->sk->sk_socket->file->f_cred;
			uid = cc->fsuid.val;
		}
	}

	/* For each nid, check policy of daddr */
	netgroup_info = get_group_info(cc->netgroup_info);
	for (i = 0; i < netgroup_info->ngroups; i++) {
		kgid_t knid = GROUP_AT(netgroup_info, i);
		gid_t nid = from_kgid_munged(user_ns, knid);

		if (blockpkt(uid, nid, daddr))
		{
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

int nfilter_init(void)
{
	printk(KERN_INFO "Loaded nfilter module\n");

	p.hook = hook_function;
	p.hooknum = NF_INET_LOCAL_OUT;
	p.pf = PF_INET;
	p.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&p);

	/* Initialize the policymap */
	rwlock_init(&ngpolicymap_rwlk);
	write_lock(&ngpolicymap_rwlk);
	init_ngpolicymap(POLICY_TABLE_SIZE);

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
