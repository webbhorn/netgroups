#include <stdio.h>
#include <stdio.h>
#include "nid.h"

int main() {

  int ret_nid = getnids();
  printf("getnid: %d\n", ret_nid);
  
  return 0;
}
