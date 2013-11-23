#ifndef NID_H
#define NID_H

/*
 * Define syscall stubs.
 *
 * The syscalls that we add to the kernel are not in libc so we have to use our
 * own stubs.
 */

long getnids(void);  /* Return nids of calling process. */

#endif

