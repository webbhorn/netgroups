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

/* Return real nid of calling process. */
long getrnid(void);

/* Copy at most nidsetsize of calling process's NIDs into netgrouplist. */
long getnids(int nidsetsize, gid_t *netgrouplist);

/* Add nid to calling process's list of nids. */
long addnid(gid_t nid);

#endif

