#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEBUG 1

unsigned long ptrace_checked(enum __ptrace_request request, pid_t pid, void *addr,
		void *data)
{
	unsigned long ret = ptrace(request, pid, addr, data);
#if DEBUG == 1
	printf("ptrace called with request: %d, pid: %d, addr: %p, data: %p resulted: %lx\n",
			request, pid, addr, data, ret);
#endif
	return ret;
}

unsigned long maps_address(pid_t pid, int prot, const char *name)
{
	FILE *f;
	char *proc, *line, permissions[4];
	size_t n;
	unsigned long address;
	unsigned int oflag = 0;

	if (pid == -1) {
		proc = strdup("/proc/self/maps");
	} else {
		asprintf(&proc, "/proc/%d/maps", pid);
	}

	f = fopen(proc, "r");

	while (getline(&line, &n, f) != EOF) {
		if (strstr(line, name) != NULL) {
			sscanf(line, "%lx-%*x %s %*s %*s %*s %*s", &address, permissions);

			if (prot == -1)
				break;

			for (int i = 0; permissions[i] != 'p'; i++) {
				switch (permissions[i]) {
				case 'r':
					oflag |= PROT_READ;
					break;
				case 'w':
					oflag |= PROT_WRITE;
					break;
				case 'x':
					oflag |= PROT_EXEC;
					break;
				default:
					break;
				}
			}

			if (prot == oflag)
				break;
		}
	}

	fclose(f);
	free(proc);

	return address;
}

int main(int argc, char *argv[])
{
	pid_t child;
	unsigned long entry_point;

	{
		ElfW(Ehdr) *ehdr;
		FILE *f;
		unsigned char buff[255] = {0};

		if (argc < 3) {
			fprintf(stderr, "%s [target] [.so]\n", argv[0]);
			return -1;
		}

		/* Read target binary. */
		f = fopen(argv[1], "r");
		if (f == NULL) {
			fprintf(stderr, "%s is not a file\n", argv[1]);
			return -1;
		}

		/* We check if the binary is an ELF file. */
		fread(buff, sizeof(buff), 1, f);
		if (memcmp(buff, ELFMAG, SELFMAG)) {
			fprintf(stderr, "%s is not an ELF\n", argv[1]);
			return -1;
		}
		fclose(f);

		/* We now have the executable header of the target ELF. */
		ehdr = (void *)buff;

		/* 
		 * `.text` section starts at 0x1000 (page aligned) but we need the actual offset
		 * of  the entry point from the start of `.text` section. Refer to `objdump`.
		 */
		entry_point = ehdr->e_entry - 0x1000;
	}

	if ((child = fork()) != 0) {
		int status;
		unsigned long word;

		/* Wait for SIGSTOP in child. */
		wait(&status);

		{
			printf("child with pid %d stopped...\n", child);

			/* Trace `execve()` syscall. */
			ptrace_checked(PTRACE_SETOPTIONS, child, NULL, (void *)PTRACE_O_TRACEEXEC);
			/* Let us continue. */
			ptrace_checked(PTRACE_CONT, child, NULL, NULL);
		}

		/* Wait before `execve()` returns, we are in the target process image now. */
		wait(&status);

		{
			/* Get the target's entry point within its own memory space. */
			entry_point += maps_address(child, PROT_READ | PROT_EXEC, argv[1]);

			printf("entry point address `_start()` of target is: 0x%lx\n", entry_point);

			/* Backup a word of data from target's entry point. */
			word = ptrace_checked(PTRACE_PEEKTEXT, child, (void *)entry_point, NULL);
			/* int 0x03 */
			ptrace_checked(PTRACE_POKETEXT, child, (void *)entry_point, (void *)0xCC);
			/* Continue, the child will send a SIGSTOP executing entry point instruction due `int 0x03` */
			ptrace_checked(PTRACE_CONT, child, NULL, NULL);
		}

		/* Wait for `int 0x03` */
		wait(&status);

		unsigned long local_libc, remote_libc, allocmem;

		{
			unsigned long remote_mmap;
			{
				/* Get the remote address of `mmap()` */
				local_libc = maps_address(-1, PROT_READ | PROT_EXEC, "libc.so");
				remote_libc = maps_address(child, PROT_READ | PROT_EXEC, "libc.so");
				unsigned long local_mmap = (unsigned long)mmap;
				/* 
				 * Why? So we avoid getting the offset directly from libc.so every time there's an update
				 * or if you're a madlad and you compile it constantly. 
				 */
				remote_mmap = remote_libc + (local_mmap - local_libc);
				printf("remote `mmap()` function address is: %p\n", (void *)remote_mmap);
			}

			struct user_regs_struct regs;

			/* Get the current value of the general-purpose registers. */
			ptrace_checked(PTRACE_GETREGS, child, NULL, &regs);

			/*
			 * Modify registers to remote call `mmap()`
			 *
			 * "To pass parameters to the subroutine, we put up to six of them into registers
			 * (in order: rdi, rsi, rdx, rcx, r8, r9). If there are more than six parameters to
			 * the subroutine, then push the rest onto the stack."
			 * - cited from https://wiki.osdev.org/CPU_Registers_x86-64
			 */
			regs.rdi = 0; // addr
			regs.rsi = 0x1000; // length
			regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC; // prot
			regs.rcx = MAP_ANONYMOUS | MAP_PRIVATE; // flags
			regs.r8 = 0; // fd
			regs.r9 = 0; // offset
			regs.rip = remote_mmap;

			/*
			 * Set the return adress to 0x0 so when the subroutine uses `ret` it will raise a signal
			 * and we can catch it.
			 *
			 * "To call the subroutine, use the call instruction. This instruction places the return
			 * address on top of the parameters on the stack, and branches to the subroutine code."
			 * - cited from https://wiki.osdev.org/CPU_Registers_x86-64
			 */
			regs.rsp -= sizeof(long);
			ptrace_checked(PTRACE_POKEDATA, child, (void *)regs.rsp, 0x0);

			/* Send our modified registers. */
			ptrace_checked(PTRACE_SETREGS, child, NULL, &regs);
			/* Let us continue. */
			ptrace_checked(PTRACE_CONT, child, NULL, NULL);

			/* Wait for that SIGSEGV caused by the 0x0 return address. */
			wait(&status);

			/* Get the current value of the general-purpose registers. */
			ptrace_checked(PTRACE_GETREGS, child, NULL, &regs);

			/*
			 * "The caller can expect to find the return value of the subroutine in the register RAX."
			 * - cited from https://wiki.osdev.org/CPU_Registers_x86-64
			 */
			allocmem = regs.rax;
			printf("remote `mmap()` returned: %p\n", (void *)allocmem);

			/* +1 to consider the \0 character of every C string. */
			unsigned long path_size = strlen(argv[2]) + 1;
			unsigned long chunks = path_size / sizeof(long);
			unsigned long remaining = path_size % sizeof(long);

			for (int i = 0; i < chunks; i++) {
				unsigned long buffer = 0;
				unsigned long offset = i * sizeof(long);

				memcpy(&buffer, argv[2] + offset, sizeof(buffer));

				ptrace_checked(PTRACE_POKEDATA, child, (void* )(allocmem + offset),
						(void *)buffer);
			}

			if (remaining != 0) {
				unsigned long offset = chunks * sizeof(long);
				unsigned long buffer = ptrace_checked(PTRACE_PEEKDATA, child, (void *)(allocmem + offset),
						NULL);

				memcpy(&buffer, argv[2] + offset, remaining);
				ptrace_checked(PTRACE_POKEDATA, child, (void* )(allocmem + offset),
						(void *)buffer);
			}
		}

		{
			unsigned long remote_dlopen;
			{
				/* Get the remote address of `dlopen()` */
				unsigned long local_dlopen = (unsigned long)dlopen;
				/* Why? Already explained it. */
				remote_dlopen = remote_libc + (local_dlopen - local_libc);
				printf("remote `dlopen()` function address is: %p\n", (void *)remote_dlopen);
			}

			struct user_regs_struct regs;

			/* Get the current value of the general-purpose registers. */
			ptrace_checked(PTRACE_GETREGS, child, NULL, &regs);

			/* Modify registers to remote call `dlopen()` */
			regs.rdi = allocmem; // filename
			/* 
			 * We need our library to be loaded completely and globally for subsequent dynamic
			 * dependencies.
			 */
			regs.rsi = RTLD_NOW | RTLD_GLOBAL; // flags
			regs.rip = remote_dlopen;

			/*
			 * Set the return adress to 0x0 so when the subroutine uses `ret` it will raise a signal
			 * and we can catch it.
			 */
			regs.rsp -= sizeof(long);
			ptrace_checked(PTRACE_POKEDATA, child, (void *)regs.rsp, 0x0);

			/* Send our modified registers. */
			ptrace_checked(PTRACE_SETREGS, child, NULL, &regs);
			/* Let us continue. */
			ptrace_checked(PTRACE_CONT, child, NULL, NULL);

			/* Wait for that SIGSEGV caused by the 0x0 return address. */
			wait(&status);

			/* Get the current value of the general-purpose registers. */
			ptrace_checked(PTRACE_GETREGS, child, NULL, &regs);

			unsigned long lib_handle = regs.rax;
			printf("remote `dlopen()` returned: %p\n", (void *)lib_handle);
		}

		{
			/* Restore the instructions we modified for the entry point. */
			ptrace_checked(PTRACE_POKETEXT, child, (void *)entry_point, (void *)word);

			/* Get the current value of the general-purpose registers. */
			struct user_regs_struct regs;
			ptrace_checked(PTRACE_GETREGS, child, NULL, &regs);

			/*
			 * Set Instruction Pointer to entry point to execute the target program as if
			 * nothing happened.
			 */
			regs.rip = entry_point;

			/* Restore the original state of the target program. */
			ptrace_checked(PTRACE_SETREGS, child, NULL, &regs);
		}

		/* Wait for keyboard input. */
		getchar();

		ptrace_checked(PTRACE_DETACH, child, NULL, NULL);
	} else {
		char *const newargv[] = { argv[1], NULL };
		char *const newenvp[] = { NULL };

		ptrace_checked(PTRACE_TRACEME, 0, NULL, NULL);

		/* PTRACE_TRACEME doesn't send a stop signal. */
		raise(SIGSTOP);
		
		/* Execute target. */
		execve(argv[1], newargv, newenvp);

		/* Child is now replaced with the target's process image by `execve()`. */
	}

	return 0;
}
