#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <dlfcn.h>

//temporarly using PTRACE
#include <sys/wait.h>
#include <sys/ptrace.h>

#define SIZE_OF_ADDRESS 32

// SYSCALL instruction in x86_64
// INT3 instruction in x86_64
#define DO_SYSCALL "\x0f\x05\xcc"  

struct user_regs_struct
{
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long rip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
  unsigned long fs_base;
  unsigned long gs_base;
  unsigned long ds;
  unsigned long es;
  unsigned long fs;
  unsigned long gs;
};

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

