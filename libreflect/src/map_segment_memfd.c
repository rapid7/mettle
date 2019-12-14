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

int map_segment(struct mapped_elf *obj, ElfW(Phdr) *phdr, const unsigned char *source) {
	ElfW(Addr) dest;
	ssize_t written;
	size_t len;
	unsigned char *mapping;
	int memfd, prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
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

	if (prot & PROT_EXEC) {
		memfd = syscall(SYS_memfd_create, "", 0);
		if (memfd == -1) {
			goto memfd_failed;
		}
		if (ftruncate(memfd, PAGE_CEIL(phdr->p_memsz)) == -1) {
			goto write_failed;
		}
		dprint("write(%d, %p, %08zx)\n", memfd, source, len);
		written = write(memfd, source, len);
		if (written != len) {
			dprint("Failed to write(): %s\n", strerror(errno));
			goto write_failed;
		}

		dprint("mmap(%p, %08zx, %08x)\n", (void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz), prot);
		mapping = mmap((void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz), prot, MAP_FIXED | MAP_PRIVATE, memfd, 0);
		if (mapping == MAP_FAILED) {
			dprint("Failed to mmap(): %s\n", strerror(errno));
			goto write_failed;
		}
		close(memfd);
	} else {
		dprint("mmap(%p, %08zx)\n", (void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz + (phdr->p_vaddr % PAGE_SIZE)));
		mapping = mmap((void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz + (phdr->p_vaddr % PAGE_SIZE)), PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (mapping == MAP_FAILED) {
			dprint("Failed to mmap(): %s\n", strerror(errno));
			goto memfd_failed;
		}
		memset(mapping, 0, PAGE_CEIL(phdr->p_memsz + (phdr->p_vaddr % PAGE_SIZE)));
		dprint("memcpy(%p, %p, %08zx)\n", (void *)dest, source, len);
		memcpy((void *)dest, source, len);

		if(mprotect((void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz + (phdr->p_vaddr % PAGE_SIZE)), prot) != 0) {
			dprint("Could not mprotect(): %s\n", strerror(errno));
			goto memfd_failed;
		}
	}

	return 0;

write_failed:
	close(memfd);

memfd_failed:
	return -1;
}
