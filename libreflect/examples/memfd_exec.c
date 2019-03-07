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

int main(int argc, char **argv)
{
	int fd;
	struct stat statbuf;
	unsigned char *data = NULL; // ELF file

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

	reflect_mfd_execv(data, argv + 1);
	return 0;
}
