#ifndef MAP_SEGMENT_H
#define MAP_SEGMENT_H

#include <elf.h>
#include <link.h>

#include "reflect_common.h"

int map_segment(struct mapped_elf *, ElfW(Phdr) *, const unsigned char *);

#endif
