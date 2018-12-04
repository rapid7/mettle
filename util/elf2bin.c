/**
 *
 * @brief Convert an ELF executable to binary image.
 * @file elf2bin.c
 *
 * This program will take, as input, an ELF executable program and
 * create a binary image of the ELF executable.  This binary image is
 * position-independent and suitable for use inside a 'hollowed' process.
 *
 * NOTE: For successful ELF to BIN conversion, this program requires
 *       the ELF executable to have been built to use the musl libc
 *       implementation, which keeps the code small and POSIX-compliant.
 *
 * Example run and output:
 *   $ ./build/tools/elf2bin build/x86_64-linux-musl/bin/sniffer build/x86_64-linux-musl/bin/sniffer.bin
 *   data @ 0x7f5f51fc5000, mapping @ 0x7f5f50ad7000
 *   memcpy(0x7f5f50ad7000, 0x7f5f51fc5000, 0004cd44)
 *   memcpy(0x7f5f50b24da0, 0x7f5f52011da0, 000017d0)
 *
 * For those interested, the code below implements the following flow:
 *
 * - ELF file is opened and mmap'd into memory (as 'data')
 * - memory for new binary image mmap'd (as 'mapping')
 * - ELF type is identified (e.g. 32 or 64-bit, little or big endian)
 * - ELF program headers, section headers, and symbol table are located
 * - ELF program headers are iterated, taking action on the following types:
 *   - PT_LOAD: segment is copied from offset in 'data' to vaddr location in 'mapping'
 *   - PT_DYNAMIC: segment location of dynamic linking info is saved ('bin_info.dynamic_linker_info')
 * - ELF sections are iterated to locate the string table
 * - ELF symbols are iterated to locate the entry point name ('_start_c') in the string table
 *   - once located, the location of the entry point is saved ('bin_info.start_function')
 * - info required for loading by the hollowed out process ('bin_info') is appended to 'mapping'
 * - binary image is written to disk
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include "util-common.h"
#include "elf.h"

#define ENTRYPOINT "_start_c"

// Copy/save relevant data/info needed for the binary image
#define MAP(LONG,INT,SHORT) \
	for(ii = 0; ii < SHORT(ehdr->e_phnum); ii++, phdr++) { \
		if(INT(phdr->p_type) == PT_LOAD) { \
			source = data + LONG(phdr->p_offset); \
			dest = mapping + LONG(phdr->p_vaddr); \
			len = LONG(phdr->p_filesz); \
			printf("memcpy(%p, %p, %08zx)\n", dest, source, len); \
			memcpy(dest, source, len); \
			used = LONG(phdr->p_memsz) + LONG(phdr->p_vaddr); \
		} else if (INT(phdr->p_type) == PT_DYNAMIC) { \
			bin_info.dynamic_linker_info = LONG(phdr->p_vaddr); \
		} \
	} \
	while (INT(shdr->sh_type) != SHT_STRTAB) shdr++; \
	while ((symb < symb_end) && strcmp((char *)((unsigned char *)ehdr + LONG(shdr->sh_offset) + INT(symb->st_name)), ENTRYPOINT) != 0) symb++; \
	if (symb < symb_end) { \
		bin_info.start_function = LONG(symb->st_value); \
	}

#define NOP(T) T

#define MAP_LE MAP(NOP,NOP,NOP)
#define MAP_BE MAP(ntohl,ntohl,ntohs)
#define MAP_BE64 MAP(bswap64,ntohl,ntohs)

uint64_t bswap64(uint64_t x)
{
	return (x << 56) | (x << 40 & 0xff000000000000ULL) | (x << 24 & 0xff0000000000ULL) | (x << 8 & 0xff00000000ULL) |
		(x >> 8 & 0xff000000ULL) | (x >> 24 & 0xff0000ULL) | (x >> 40 & 0xff00ULL) | (x >> 56);
}

int main(int argc, char **argv)
{
	int fd;
	struct stat statbuf;
	unsigned char *data; // ELF file
	unsigned char *mapping; // target memory location
	size_t len, used = 0;
	int ii;
	unsigned char *source, *dest;

	Elf32_Ehdr *arch;

	if(argc < 3) {
		printf("elf2bin [input file] [output file]\n");
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

	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(data == MAP_FAILED) {
		printf("Unable to read ELF file in: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(fd);

	// Setup area in memory to contain the new binary image
	mapping = calloc(1, 0x1000000);
	if(mapping == MAP_FAILED) {
		printf("Failed to mmap(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("data @ %p, mapping @ %p\n", data, mapping);

	// Locate ELF program and section headers, and also the symbol table
	arch = (Elf32_Ehdr *)data;

	struct bin_info bin_info = {
		.start_function = 0,
		.dynamic_linker_info = 0,
		.magic_number = BIN_MAGIC_NUMBER
	};
	if (arch->e_ident[EI_CLASS] == ELFCLASS32) {
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)data;
		Elf32_Phdr *phdr = (Elf32_Phdr *)(data + ehdr->e_phoff);
		Elf32_Shdr *shdr = (Elf32_Shdr *)(data + ehdr->e_shoff);
		Elf32_Sym  *symb, *symb_end;

		if (arch->e_ident[EI_DATA] == ELFDATA2LSB) {
			while (shdr->sh_type != SHT_SYMTAB) shdr++;
			symb = (Elf32_Sym *)(data + shdr->sh_offset);
			symb_end = (Elf32_Sym *)((void *)symb + shdr->sh_size);
			MAP_LE
		} else {
			phdr = (Elf32_Phdr *)(data + ntohl(ehdr->e_phoff));
			shdr = (Elf32_Shdr *)(data + ntohl(ehdr->e_shoff));
			while (ntohl(shdr->sh_type) != SHT_SYMTAB) shdr++;
			symb = (Elf32_Sym *)(data + ntohl(shdr->sh_offset));
			symb_end = (Elf32_Sym *)((void *)symb + ntohl(shdr->sh_size));
			MAP_BE
		}
	} else {
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
		Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);
		Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
		Elf64_Sym  *symb, *symb_end;

		if (arch->e_ident[EI_DATA] == ELFDATA2LSB) {
			while (shdr->sh_type != SHT_SYMTAB) shdr++;
			symb = (Elf64_Sym *)(data + shdr->sh_offset);
			symb_end = (Elf64_Sym *)((void *)symb + shdr->sh_size);
			MAP_LE
		} else {
			phdr = (Elf64_Phdr *)(data + bswap64(ehdr->e_phoff));
			shdr = (Elf64_Shdr *)(data + bswap64(ehdr->e_shoff));
			while (ntohl(shdr->sh_type) != SHT_SYMTAB) shdr++;
			symb = (Elf64_Sym *)(data + bswap64(shdr->sh_offset));
			symb_end = (Elf64_Sym *)((void *)symb + bswap64(shdr->sh_size));
			MAP_BE64
		}
	}

	if (bin_info.start_function == 0) {
		printf("Unable to locate entry point '%s' in binary image\n", ENTRYPOINT);
		exit(EXIT_FAILURE);
	}

	// Append info the loader needs in order to use this binary image
	memcpy((mapping + used), &bin_info, sizeof(bin_info));
	used += sizeof(bin_info);

	fd = open(argv[2], O_RDWR|O_TRUNC|O_CREAT, 0644);
	if(fd == -1) {
		printf("Unable to dump memory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(write(fd, mapping, used) != used) {
		printf("Unable to complete memory dump\n");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}
