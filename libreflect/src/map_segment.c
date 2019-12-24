#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include <linux/memfd.h>

#include <reflect.h>
#include "map_elf.h"
#include "map_segment.h"

// Map an ELF segment, using a naive mmap(2) for all segment types

int map_segment(struct mapped_elf *obj, ElfW(Phdr) *phdr, const unsigned char *source) {
	ElfW(Addr) dest;
	size_t len, page_rounded_len;
	int prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
		((phdr->p_flags & PF_W) ? PROT_WRITE: 0) |
		((phdr->p_flags & PF_X) ? PROT_EXEC : 0));

	// Caluate the destination. If the object is position independent,
	// phdr->p_vaddr is a memory offset, otherwise it is an actual address
	if (obj->pie) {
		dest = (size_t) obj->ehdr + phdr->p_vaddr;
	} else {
		dest = phdr->p_vaddr;
	}

	len = phdr->p_filesz;
	page_rounded_len = PAGE_CEIL(phdr->p_memsz + (phdr->p_vaddr % PAGE_SIZE));

	if (prot & PROT_EXEC) {
		// This will try to use mmap as a fallback if fancier methods fail. May
		// also try mmap twice, but if it already failed that won't make things
		// worse.
		if (map_executable_segment(dest, source, page_rounded_len, len, prot) == 0) {
			return 0;
		}
	}

	return mmap_segment(dest, source, page_rounded_len, len, prot);
}

int mmap_segment(ElfW(Addr) dest, const unsigned char *source, size_t page_rounded_len, size_t len, int prot) {
	// Common to all *nix platforms, and the best choice for read-only or
	// read-write memory. Can also be used as a fallback for executable memory
	// if a more sophisticated method fails or is not supported.

	unsigned char *mapping;

	dprint("mmap(%p, %08zx)\n", (void *)PAGE_FLOOR(dest), page_rounded_len);
	mapping = mmap((void *)PAGE_FLOOR(dest), page_rounded_len, PROT_WRITE, \
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (mapping == MAP_FAILED) {
		dprint("Failed to mmap(): %s\n", strerror(errno));
		goto map_failed;
	}

	// Initialize the whole thing, but only copy the size on disk out of
	// the source.
	memset(mapping, 0, page_rounded_len);
	dprint("memcpy(%p, %p, %08zx)\n", (void *)dest, source, len);
	memcpy((void *)dest, source, len);

	// Change to the specified permissions
	if(mprotect((void *)PAGE_FLOOR(dest), page_rounded_len, prot) != 0) {
		dprint("Could not mprotect(): %s\n", strerror(errno));
		goto mprotect_failed;
	}

	return 0;

mprotect_failed:
map_failed:
	return -1;
}
