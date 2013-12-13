#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nid.h"

int main(int argc, char *argv[]) {
  if (argc < 3) {
    printf("Usage: nidlaunch NID pgm\n");
    exit(-1);
  }

  gid_t nid = atoi(argv[1]);
  if(addnid(nid) < 0) {
    printf("Error adding nid %d.\n", atoi(argv[1]));
    exit(-1);
  }

  execvp(argv[2], &argv[2]);

  return 0;
}

