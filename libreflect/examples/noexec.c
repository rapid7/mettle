#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <reflect.h>

int main(int argc, char **argv, char **env)
{
	int fd;
	struct stat statbuf;
	unsigned char *data = NULL; // ELF file
	struct mapped_elf exe = {0}, interp = {0};


	// TODO: network vvvvv
	if(argc < 2) {
		printf("exec.bin [input file]\n");
		exit(EXIT_FAILURE);
	}

	// Load input ELF executable into memory
	fd = open(argv[1], O_RDONLY);
	if(fd == -1) {
		printf("Failed to open %s: %s\n", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(fstat(fd, &statbuf) == -1) {
		printf("Failed to fstat(fd): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// TODO: read?
	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(data == MAP_FAILED) {
		printf("Unable to read ELF file in: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(fd);

	// TODO: network ^^^^^

	map_elf(data, &exe);
	munmap(data, statbuf.st_size);
	if (exe.ehdr == MAP_FAILED) {
		printf("Unable to map ELF file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (exe.interp) {
		// Load input ELF executable into memory
		fd = open(exe.interp, O_RDONLY);
		if(fd == -1) {
			printf("Failed to open %p: %s\n", exe.interp, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if(fstat(fd, &statbuf) == -1) {
			printf("Failed to fstat(fd): %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if(data == MAP_FAILED) {
			printf("Unable to read ELF file in: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		printf("Mapped ELF interp file in: %s\n", exe.interp);

		close(fd);

		map_elf(data, &interp);
		munmap(data, statbuf.st_size);
		if (interp.ehdr == MAP_FAILED) {
			printf("Unable to map interpreter for ELF file: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

	} else {
		interp = exe;
	}


	// copy and modify our initial argv and env to reuse

	size_t *new_stack = (size_t *)argv - 1;

	// If allocating a new stack, be sure to give it lots of space since the OS
	// won't always honor MAP_GROWSDOWN:
	//size_t *new_stack = (void *) (2047 * PAGE_SIZE + mmap(0, 2048 * PAGE_SIZE,
	//	PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN, -1, 0));
	// Or use the high level API:
	// reflect_execv(data, argv + 1);

	stack_setup(new_stack, argc - 1, argv + 1, env, NULL,
			exe.ehdr, interp.ehdr);

	jump_with_stack(interp.entry_point, new_stack);
	return 0;
}
