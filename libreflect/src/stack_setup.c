#include <elf.h>
#include <link.h>
#include <sys/types.h>
#include <sys/auxv.h>

#include <reflect.h>

#include "reflect_common.h"

/**
 * Functions that create a sane stack suitable for most kinds of programs on
 * most platforms. The function in this file allocate no memory beyond their
 * stack frame and execute no system calls. They are purely bookkeeping and
 * will not fail if passed valid memory addresses.
 **/

// Builds the foundation of a minimally-viable auxiliary vector when we have
// none. Requires 20 * size_of(size_t) bytes of memory.
void synthetic_auxv(size_t *auxv)
{
	// Save this value as it might be overwritten already as original auxv
	// is reused and we don't know what order the entries are in.
	unsigned long at_sysinfo_ehdr_value = getauxval(AT_SYSINFO_EHDR);

	auxv[0] = AT_BASE;
	auxv[2] = AT_PHDR;
	auxv[4] = AT_ENTRY;
	auxv[6] = AT_PHNUM;
	auxv[8] = AT_PHENT;
	auxv[10] = AT_PAGESZ; auxv[11] = PAGE_SIZE;
	auxv[12] = AT_SECURE;
    // Required for stack cookies on glibc, hope your payload doesn't get popped
	auxv[14] = AT_RANDOM; auxv[15] = (size_t)auxv;
	auxv[16] = AT_SYSINFO_EHDR; auxv[17] = at_sysinfo_ehdr_value;
	auxv[18] = AT_NULL; auxv[19] = 0;
}

// Minimum modifications for a sane auxiliary vector to run interpreted dynamic
// programs. May not work on all architectures, not multilib-capable.
//
// For static programs, pass the executable image as both `exe` and `interp`
void load_program_info(size_t *auxv, ElfW(Ehdr) *exe, ElfW(Ehdr) *interp)
{
	int ii;
	size_t exe_loc = (size_t) exe, interp_loc = (size_t) interp;

	for (ii = 0; auxv[ii]; ii += 2) {
		switch (auxv[ii]) {
			case AT_BASE:
				auxv[ii + 1] = interp_loc;
				break;
			case AT_PHDR:
				// When this points to a different place than the executable in
				// AT_BASE, the dynamic linker knows that another program is
				// pre-loaded by whoever invoked it
				auxv[ii + 1] = exe_loc + exe->e_phoff;
				break;
			case AT_ENTRY:
				// If the exe is position-independent, `e_entry` is an offset
				// and we need to add it to the base of image
				auxv[ii + 1] = (exe->e_entry < exe_loc ? exe_loc + exe->e_entry : exe->e_entry);
				break;
			case AT_PHNUM:
				auxv[ii + 1] = exe->e_phnum;
				break;
			case AT_PHENT:
				auxv[ii + 1] = exe->e_phentsize;
				break;
			case AT_SECURE:
				auxv[ii + 1] = 0;
				break;
		}
	}
}

// If auxv is NULL, a synthetic one will be added.
// Can cannibalize an old stack in place IF AND ONLY IF:
//   * argc <= argc of original stack AND
//   * env is shorter or the same length as the original stack
void stack_setup(size_t *stack_base, int argc, char **argv, char **env, size_t *auxv,
		ElfW(Ehdr) *exe, ElfW(Ehdr) *interp)
{
	size_t *auxv_base;
	int ii;

	dprint("New stack: %p\n", (void *)stack_base);

	stack_base[0] = argc;
	dprint("  0x%08zx\n", stack_base[0]);

	for (ii = 0; ii < argc; ii++) {
		stack_base[1 + ii] = (size_t)argv[ii];
		dprint("  0x%08zx\n", stack_base[1 + ii]);
	}
	stack_base[1 + ii] = 0;
	dprint("  0x%08zx\n", stack_base[1 + ii]);

	for (ii = 0; env[ii]; ii++) {
		stack_base[1 + argc + ii] = (size_t)env[ii];
		dprint("  0x%08zx\n", stack_base[1 + argc + ii]);
	}
	stack_base[1 + argc + ii] = 0;
	dprint("  0x%08zx\n", stack_base[1 + argc + ii]);

	auxv_base = stack_base + 1 + argc + ii + 1;

	if(auxv) {
		for (ii = 0; auxv[ii]; ii++) {
			auxv_base[ii] = auxv[ii];
		}
		auxv_base[ii] = AT_NULL;
		auxv_base[ii + 1] = 0;
	} else {
		synthetic_auxv(auxv_base);
	}

	load_program_info(auxv_base, exe, interp);
#ifdef DEBUG
	for (ii = 0; auxv_base[ii]; ii += 2) {
		dprint("  0x%08zx\t0x%08zx\n", auxv_base[ii], auxv_base[ii+1]);
	}
#endif
}
