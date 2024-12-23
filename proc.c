#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>

unsigned long module_address(pid_t pid, int prot, const char *name)
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
