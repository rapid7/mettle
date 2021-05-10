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

// Map an ELF segment, using a memfd-backed mapping when executable for the
// broadest Linux attack surface.

int memfd_segment(ElfW(Addr) dest, const unsigned char *source, size_t page_rounded_len, size_t len, int prot) {
	ssize_t written;
	unsigned char *mapping;
	int memfd;

	// NOTE: passing a name of normal stuff that uses memfds may help in the future
	memfd = syscall(SYS_memfd_create, "", 0);
	if (memfd == -1) {
		goto memfd_failed;
	}
	if (ftruncate(memfd, page_rounded_len) == -1) {
		goto write_failed;
	}
	// Write the code from the source executable to the file
	dprint("write(%d, %p, %08zx)\n", memfd, source, len);
	written = write(memfd, source, len);
	if (written != len) {
		dprint("Failed to write(): %s\n", strerror(errno));
		goto write_failed;
	}

	// Map the code into place as if we were mapping it from a normal file
	dprint("mmap(%p, %08zx, %08x)\n", (void *)PAGE_FLOOR(dest), page_rounded_len, prot);
	mapping = mmap((void *)PAGE_FLOOR(dest), page_rounded_len, prot, MAP_FIXED | MAP_PRIVATE, memfd, 0);
	if (mapping == MAP_FAILED) {
		dprint("Failed to mmap(): %s\n", strerror(errno));
		goto write_failed;
	}

	close(memfd);
	return 0;

write_failed:
	close(memfd);

memfd_failed:
	return -1;
}
