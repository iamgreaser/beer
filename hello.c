#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	int i;

	printf("Hello World! By the way, you might want these things...\n");
	printf("Argument count is %i.\n", argc);
	for(i = 0; i < argc; i++)
		printf("Arg %i out of %i: [%s]\n", i+1, argc, argv[i]);
	
	return 0;
}

