#include <stdio.h>
#include <sys/mman.h>

void my_function()
{
	printf("Hello, World! %p\n", mmap);
}

int main(void)
{
	/*while (1) my_function();*/
	my_function();

	return 0;
}
