#ifndef REFLECT_H
#define REFLECT_H

#include <elf.h>
#include <link.h>

/*
 * High-level interface
 */
void reflect_execv(const unsigned char *elf, char **argv);
void reflect_execve(const unsigned char *elf, char **argv, char **env);
void reflect_execves(const unsigned char *elf, char **argv, char **env, size_t *stack);

/*
 * ELF mapping interface
 */
struct mapped_elf {
	ElfW(Ehdr) *ehdr;
	ElfW(Addr) entry_point;
	char *interp;
};

void map_elf(const unsigned char *data, struct mapped_elf *obj);

/*
 * Stack creation and setup interface
 */
void synthetic_auxv(size_t *auxv);
void modify_auxv(size_t *auxv, ElfW(Ehdr) *exe, ElfW(Ehdr) *interp);
void stack_setup(size_t *stack_base, int argc, char **argv, char **env, size_t *auxv,
		ElfW(Ehdr) *exe, ElfW(Ehdr) *interp);

/*
 * Custom flow control
 */

void jump_with_stack(size_t dest, size_t *stack);

#endif
