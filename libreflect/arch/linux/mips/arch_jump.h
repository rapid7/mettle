#ifndef ARCH_JUMP_H
#define ARCH_JUMP_H

#define JUMP_WITH_STACK(jump_addr, jump_stack) \
	__asm__ volatile ( \
			"move $sp, %[stack]\n" /* reset the stack to our pivot */ \
			"jr %[entry]\n" /* Up, up, and away! */ \
			"nop" /* The assembler will normally reorder the move and jump to take */ \
			/* advantage of the delay slot, but stash this here just in case */ \
			: /* None  */ \
			: [stack] "r" (jump_stack), [entry] "r" (jump_addr) \
			: "memory" \
			)

#endif
