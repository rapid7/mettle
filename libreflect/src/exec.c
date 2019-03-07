#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <reflect.h>

#include "reflect_common.h"

extern char **environ;

void reflect_execv(const unsigned char *elf, char **argv) {
	dprint("Using default environment %p\n", (void *)environ);
	reflect_execve(elf, argv, NULL);
}

void reflect_execve(const unsigned char *elf, char **argv, char **env) {
	// When allocating a new stack, be sure to give it lots of space since the OS
	// won't always honor MAP_GROWSDOWN
	size_t *new_stack = (void *) (2047 * PAGE_SIZE +  (char *) mmap(0, 2048 * PAGE_SIZE,
		PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN, -1, 0));

	dprint("Allocated new stack %p\n", (void *)new_stack);
	reflect_execves(elf, argv, env, new_stack);
}

void reflect_execves(const unsigned char *elf, char **argv, char **env, size_t *stack) {
	int fd;
	struct stat statbuf;
	unsigned char *data = NULL;
	size_t argc;

	struct mapped_elf exe = {0}, interp = {0};

	if (!is_compatible_elf((ElfW(Ehdr) *)elf)) {
		abort();
	}


	if (env == NULL) {
		env = environ;
	}

	map_elf(elf, &exe);
	if (exe.ehdr == MAP_FAILED) {
		dprint("Unable to map ELF file: %s\n", strerror(errno));
		abort();
	}

	if (exe.interp) {
		// Load input ELF executable into memory
		fd = open(exe.interp, O_RDONLY);
		if(fd == -1) {
			dprint("Failed to open %p: %s\n", exe.interp, strerror(errno));
			abort();
		}

		if(fstat(fd, &statbuf) == -1) {
			dprint("Failed to fstat(fd): %s\n", strerror(errno));
			abort();
		}

		data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if(data == MAP_FAILED) {
			dprint("Unable to read ELF file in: %s\n", strerror(errno));
			abort();
		}
		close(fd);

		map_elf(data, &interp);
		munmap(data, statbuf.st_size);
		if (interp.ehdr == MAP_FAILED) {
			dprint("Unable to map interpreter for ELF file: %s\n", strerror(errno));
			abort();
		}
		dprint("Mapped ELF interp file in: %s\n", exe.interp);
	} else {
		interp = exe;
	}

	for (argc = 0; argv[argc]; argc++);

	stack_setup(stack, argc, argv, env, NULL,
			exe.ehdr, interp.ehdr);

	jump_with_stack(interp.entry_point, stack);
}
