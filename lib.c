#include <stdio.h>

__attribute__((constructor)) void on_load()
{
	printf("Hello from library\n");
}

__attribute__((destructor)) void on_unload()
{
	printf("Bye from library\n");
}
