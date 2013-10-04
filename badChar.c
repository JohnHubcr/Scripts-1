#include<stdio.h>

main(int argc, char **argv)
{
	int c = 0;

	printf("\"");
	while (c<= 255)
		printf("\\x%.2x", c++);
	printf("\"");

	return 0;
}