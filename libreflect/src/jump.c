#include <stdlib.h>

#include <reflect.h>

#include "arch_jump.h"

inline void __attribute ((noreturn)) jump_with_stack(size_t dest, size_t *stack)
{
	JUMP_WITH_STACK(dest, stack);
	// If we didn't jump, something went wrong
	abort();
}
