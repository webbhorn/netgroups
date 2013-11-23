#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
  int nid = syscall(__NR_getnids);
  printf("%d\n", nid);
  
  return 0;
}
