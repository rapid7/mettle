#ifndef MAP_ELF_H
#define MAP_ELF_H

#include <elf.h>
#include <link.h>

#include "reflect_common.h"

#define PAGE_FLOOR(addr) ((addr) & (-PAGE_SIZE))
#define PAGE_CEIL(addr) (PAGE_FLOOR((addr) + PAGE_SIZE - 1))

#endif
