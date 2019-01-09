#ifndef ARCH_JUMP_H
#define ARCH_JUMP_H

#define JUMP_WITH_STACK(jump_addr, jump_stack) \
	__asm__ volatile ( \
			"move $sp, %[stack]\n" /* reset the stack to our pivot */ \
			"jr %[entry]" /* Up, up, and away! */ \
			: /* None  */ \
			: [stack] "r" (jump_stack), [entry] "r" (jump_addr) \
			: "memory" \
			)

#endif
