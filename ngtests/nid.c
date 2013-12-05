#include "nid.h"

#include <sys/syscall.h>
#include <unistd.h>

/*
 * Implementation of nid syscall stubs.
 */

long getrnid(void) {
  return syscall(__NR_getrnid);
}

long getnids(int nidsetsize, gid_t *netgrouplist) {
  return syscall(__NR_getnids, nidsetsize, netgrouplist);
}

long addnid(gid_t nid) {
  return syscall(__NR_addnid, nid);
}

