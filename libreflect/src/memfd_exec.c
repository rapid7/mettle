#include <elf.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <reflect.h>

#include "reflect_common.h"

extern char **environ;

void reflect_mfd_execv(const unsigned char *elf, char **argv) {
	dprint("Using default environment %p\n", (void *)environ);
	reflect_mfd_execve(elf, argv, environ);
}

void reflect_mfd_execve(const unsigned char *elf, char **argv, char **env) {
	int out, ii;
	ssize_t l = 0;
	size_t end = 0, written = 0;
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) elf;
	ElfW(Phdr) *phdr = (ElfW(Phdr) *)(elf + ehdr->e_phoff);

	if (!is_compatible_elf((ElfW(Ehdr) *)elf)) {
		abort();
	}

	// XXX: Assumes normal elf files with the important data before the end of
	// the last LOAD segment
	for(ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {
		if(phdr->p_type == PT_LOAD) {
			if (end < phdr->p_offset + phdr->p_filesz) {
				end = phdr->p_offset + phdr->p_filesz;
			}
		}
	}

	out = syscall(SYS_memfd_create, "", MFD_CLOEXEC);
	if (ftruncate(out, end) == -1) {
		dprint("Failed to resize memory file: %s\n", strerror(errno));
		abort();
	}

	while (written < end) {
		l = write(out, elf + written, end - written);
		if (l == -1) {
		  dprint("Failed to write memory file: %s\n", strerror(errno));
		  abort();
		}
		written += l;
	}

	syscall(SYS_execveat, out, "", argv, env, AT_EMPTY_PATH);
}

