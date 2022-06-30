#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "interface/if_os.h"
#include "lh_common.h"

void otherfunction(int a, char *s) {
	LH_PRINT("and this one is another function, which is exported too.");
	LH_PRINT("%%s is: %s, %%d is %d\n", s, a);
}

int testfunction(int a, char *s) {
	LH_PRINT("inside the original test function.");
	LH_PRINT("we just print some more.");
	LH_PRINT("in order to make this function");
	LH_PRINT("big enough, so we can hook it later");
	LH_PRINT("%%s is: %s, %%d is %d\n", s, a);
	otherfunction(a, s);
	return 0;
}

void run() {
	char *stuff = "test buffer";
	int a = 1;
	while (1) {
		int ret = testfunction(a, stuff);
		LH_PRINT("RETVAL: %d", ret);
		a++;
		sleep(1);
	}

}
int main(int argc, char *argv[]) {
	LH_PRINT("Hello! We are a simple test appliaction.");
	LH_PRINT("malloc is: %08x", malloc);
	LH_PRINT("This is a very basic test, in order to demonstrate");
	LH_PRINT("the power of the awesome hooker library.\n");

	run();

	return 0;
}

/*
  char *s = (char*)malloc(100);
dlopen(s, 0);
*/
