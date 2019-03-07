#ifndef ARCH_JUMP_H
#define ARCH_JUMP_H

#define JUMP_WITH_STACK(jump_addr, jump_stack) \
	__asm__ volatile ( \
			"mr %%r1, %[stack]\n" /* reset the stack to our pivot */ \
			"mtlr %[entry]\n" /* Set up the special register we can jump to */ \
			"blr" /* Up, up, and away! */ \
			: /* None  */ \
			: [stack] "r" (jump_stack), [entry] "r" (jump_addr) \
			: "memory" \
			)

#endif
