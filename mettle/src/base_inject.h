#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <dlfcn.h>
#include <sigar.h>
#include <sigar_private.h>
#include <sigar_util.h>

#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define SIZE_OF_ADDRESS 32
#define SIGAR_PROC_FILENAME(buffer, pid, fname) \
    sigar_proc_filename(buffer, sizeof(buffer), \
                        pid, fname, SSTRLEN(fname))

// SYSCALL/INT3 stub: triggers the syscall then stops for ptrace to read result
#if defined(__x86_64__)
#define DO_SYSCALL "\x0f\x05\xcc"   // syscall; int3
#elif defined(__i386__)
#define DO_SYSCALL "\xcd\x80\xcc"   // int 0x80; int3
#endif

typedef struct process_section {
    unsigned long start_address;
    unsigned long end_address;
} process_section_t, *process_section_ptr;

typedef struct writable_section {
	int pid;
	process_section_t sections[255];
} writable_section_t, *writable_section_ptr;

int migrate_support();

int is_root();

int get_yama_ptrace_scope();

int migrate(int pid, char * migrate_stub, size_t migrate_stub_length, char * payload, size_t payload_length, const char * uuid, int fd);

