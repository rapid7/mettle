#ifndef ARCH_JUMP_H
#define ARCH_JUMP_H

#define JUMP_WITH_STACK(jump_addr, jump_stack) \
	__asm__ volatile ( \
			"lgr %%r15, %[stack]\n" /* reset the stack to our pivot */ \
			"br %[entry]" /* Up, up, and away! */ \
			: /* None  */ \
			: [stack] "r" (jump_stack), [entry] "r" (jump_addr) \
			: "memory" \
			)

#endif
