#include "nid.h"

#include <sys/syscall.h>
#include <unistd.h>

/*
 * Implementation of nid syscall stubs.
 */

long getnids(void) {
  return syscall(__NR_getnids);
}

long setnids(nid_t nid) {
  return syscall(__NR_setnids, nid);
}

long getnetgroups(int nidsetsize, gid_t *netgrouplist) {
  return syscall(__NR_getnetgroups, nidsetsize, netgrouplist);
}

long addnid(gid_t nid) {
  return syscall(__NR_addnid, nid);
}
