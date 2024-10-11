#include <stdio.h>
#include <sys/mman.h>

void my_function()
{
	printf("Hello, World!\n");
}

int main(void)
{
	while (1) my_function();

	return 0;
}
