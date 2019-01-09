#ifndef ARCH_JUMP_H
#define ARCH_JUMP_H

#define JUMP_WITH_STACK(jump_addr, jump_stack) \
	__asm__ volatile ( \
			"mov %[stack], %%esp\n" /* reset the stack to our pivot */ \
			"xor %%edx, %%edx\n" /* zero edx so no one thinks it's a function pointer for cleanup */ \
			"jmp *%[entry]" /* Up, up, and away! */ \
			: /* None  */ \
			: [stack] "r" (jump_stack), [entry] "r" (jump_addr) \
			: "edx", "memory" \
			)

#endif
