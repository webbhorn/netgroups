#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
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

	int pid = fork();
	if (pid == 0) {
		printf("Child nid is %ld\n", getnids());
	} else {
		printf("Parent nid is %ld\n", getnids());
	}

	int status;
	wait(&status);

  return 0;
}
