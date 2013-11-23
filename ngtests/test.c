#include <stdio.h>
#include <stdlib.h>
#include "nid.h"

/* Test set and get nid. */
int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Need nid.\n");
    exit(-1);
  }
  const int nid = atoi(argv[1]);

  if (setnids(nid) < 0)
    printf("error\n");

  printf("%d\n", getnids());
  return 0;
}
