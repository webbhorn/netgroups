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

int blockpkt(uid_t uid, gid_t nid, __be32 addr, int dbg)
{
	int print_debug;
	struct _list *policy;
	int block;

	read_lock(&ngpolicymap_rwlk);
	policy = get_ngpolicy(uid, nid);
	if (dbg)
		printk(KERN_INFO "policy addr: %p\n", policy);
	if (!policy) {
		read_unlock(&ngpolicymap_rwlk);
		return false;
	}

	if (dbg)
		printk(KERN_INFO "policy mode: %d\n", policy->val->mode);
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
	kuid_t kuid = current_uid();
	struct pid * pid = current->pid;
	uid_t uid = from_kuid_munged(user_ns, kuid);

	__be32 ip = make_ipaddr(93, 184, 216, 119);
	if (ip == daddr) {
		printk(KERN_INFO "The uid is %d and the pid is %d\n", uid, pid);
		printk(KERN_INFO "Are we in an interrupt? %d\n", in_interrupt());
		printk(KERN_INFO "Are we in a software interrupt? %d\n", in_softirq());

		if (! skb->sk || skb->sk->sk_state == TCP_TIME_WAIT) {
			printk(KERN_INFO "Was null pointer!!!\n");
			return NF_DROP;
		}
		if (skb->sk->sk_socket && skb->sk->sk_socket->file) {

			printk(KERN_INFO "\n\n\n");
			printk(KERN_INFO "skb: %p\n", skb);
			printk(KERN_INFO "sk: %p\n", skb->sk);
			printk(KERN_INFO "sk_socket: %p\n", skb->sk->sk_socket);
			printk(KERN_INFO "file: %p\n", skb->sk->sk_socket->file);
			printk(KERN_INFO "f_cred: %p\n", skb->sk->sk_socket->file->f_cred);
			printk(KERN_INFO "\n\n\n");
			const struct cred *cred = skb->sk->sk_socket->file->f_cred;
			printk(KERN_INFO "!!!\nUID=%u\nGID=%u\n!!!\n\n",
				cred->fsuid.val,
				cred->fsgid.val);
			printk(KERN_INFO "uid before: %d\n", uid);
			if (!uid) {
				uid = cred->fsuid.val;
				cc = skb->sk->sk_socket->file->f_cred;
			}
			printk(KERN_INFO "uid after: %d\n", uid);
		} else {
			printk(KERN_INFO "Caught the derefence fail!\n");
		}
	}

	/* For each nid, check policy of daddr */
	struct group_info *netgroup_info = get_group_info(cc->netgroup_info);
	int dbg = 0;
	for (i = 0; i < netgroup_info->ngroups; i++) {
		kgid_t knid = GROUP_AT(netgroup_info, i);
		gid_t nid = from_kgid_munged(user_ns, knid);
		printk("Checking policy for nid %d\n", nid);
		if (ip == daddr) {
			printk(KERN_INFO "One nid is %d\n", nid);
			dbg =1;
		}


		if (blockpkt(uid, nid, daddr, dbg))
		{
			if (ip == daddr) {
				printk(KERN_INFO "Dropping that shit\n");
			}
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
