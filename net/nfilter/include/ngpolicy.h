#ifndef _NGPOLICY_H_
#define _NGPOLICY_H_

#include <linux/uidgid.h>
#include <linux/spinlock.h>
#include <uapi/linux/ip.h>

extern rwlock_t ngpolicymap_rwlk;

typedef enum {
	NG_WHITELIST,
	NG_BLACKLIST
} ngmode_t;

struct _nidkey {
	uid_t uid;
	gid_t nid;
};

struct _nidpolicy {
	ngmode_t mode;
	int size;
	struct _ip_list *ips;
};

struct _ip_list {
	__be32 addr;
	struct _ip_list *next;
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

extern int	init_ngpolicymap(int size);
extern struct _list* get_ngpolicy(uid_t uid, gid_t nid);
extern int	put_ngpolicy(uid_t uid, gid_t nid, ngmode_t mode);
extern void	free_ngpolicymap(void);
extern int	ngpolicy_contains_ip(struct _nidpolicy *policy, __be32 addr);
extern int	add_ip_to_ngpolicy(struct _nidpolicy *policy, __be32 addr);
extern __be32	make_ipaddr(__u8 b1, __u8 b2, __u8 b3, __u8 b4);

#endif  /* _NGPOLICY_H_ */

