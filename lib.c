#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern unsigned long module_address(pid_t pid, int prot, const char *name);

void *page_floor(void *address)
{
	return (void *)((unsigned long)address & -getpagesize());
}

void inline_hook(void *orig_func, void *hook_func)
{
	char jmp_bytes[] = {
		/* mov rax, 0xCCCCCCCCCCCCCCCC */
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		/* jmp rax */
		0xFF, 0xE0
	};
	int page_size = getpagesize();

	memcpy(jmp_bytes + 2, (unsigned long *)&hook_func, sizeof(unsigned long));

	mprotect(page_floor(orig_func), page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy(orig_func, jmp_bytes, sizeof(jmp_bytes));
	mprotect(page_floor(orig_func), page_size, PROT_READ | PROT_EXEC);
}

void my_hook_function()
{
	printf("Hello from hooked function!\n");
}

__attribute__((constructor)) void on_load()
{
	printf("Hello from library\n");

	void *text_segment = (void *)module_address(-1, PROT_READ | PROT_EXEC, "hello");
	void *my_function = text_segment + 0x1139 - 0x1000;

	inline_hook(my_function, my_hook_function);
}

__attribute__((destructor)) void on_unload()
{
	printf("Bye from library\n");
}
