#ifndef MAP_ELF_H
#define MAP_ELF_H

#include <elf.h>
#include <link.h>

#include "reflect_common.h"

#define PAGE_FLOOR(addr) ((addr) & (-PAGE_SIZE))
#define PAGE_CEIL(addr) (PAGE_FLOOR((addr) + PAGE_SIZE - 1))


/* ELF compatibility checks */
#if UINTPTR_MAX > 0xffffffff
#define ELFCLASS_NATIVE ELFCLASS64
#else
#define ELFCLASS_NATIVE ELFCLASS32
#endif

#include <arpa/inet.h>
#define ELFDATA_NATIVE ((htonl(1) == 1) ? ELFDATA2MSB : ELFDATA2LSB)

#endif
