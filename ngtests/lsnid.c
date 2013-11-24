#include <stdio.h>
#include <unistd.h>

#include "nid.h"

int main() {

  int i;
  long ret_nid = getnids();
  printf("%lu\n", ret_nid);

  gid_t grps[32] = {0};
  long nngroups = getnetgroups(32, grps);

  for (i=0; i < nngroups; i++)
    printf("%i ", (int)grps[i]);
  if (nngroups)
    printf("\n");

  return 0;
}
