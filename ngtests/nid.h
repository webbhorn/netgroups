#ifndef NID_H
#define NID_H

#include <stdint.h>
#include <unistd.h>

/*
 * Define syscall stubs.
 *
 * The syscalls that we add to the kernel are not in libc so we have to use our
 * own stubs.
 */

typedef uint32_t nid_t;

long getnids(void);  /* Return nids of calling process. */
long setnids(nid_t nid);  /* Set nid of calling process to nid. */

long getnetgroups(int nidsetsize, gid_t *netgrouplist);
long addnid(gid_t nid);

#endif

