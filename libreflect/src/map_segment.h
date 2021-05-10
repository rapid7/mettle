#ifndef MAP_SEGMENT_H
#define MAP_SEGMENT_H

#include <elf.h>
#include <link.h>

#include <reflect.h>

#include "reflect_common.h"

int map_segment(struct mapped_elf *, ElfW(Phdr) *, const unsigned char *);

#if !REFLECT_HAVE_MEMFD
#define map_executable_segment mmap_segment
#else
#define map_executable_segment memfd_segment
int memfd_segment(ElfW(Addr), const unsigned char *, size_t, size_t, int);
#endif

int mmap_segment(ElfW(Addr), const unsigned char *, size_t, size_t, int);
#endif
