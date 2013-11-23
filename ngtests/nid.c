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
