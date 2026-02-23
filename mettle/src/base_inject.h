#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>

//temporarly using PTRACE
#include <sys/wait.h>
#include <sys/ptrace.h>

#define SIZE_OF_ADDRESS 12

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


int is_root();

int inject_procfs();

int migrate(int pid, char * migrate_stub, size_t migrate_stub_length, char * payload, size_t payload_length, const char * uuid);
int get_process_sections();

unsigned long find_codecave();

void read_process_memory();

int is_readable(char * line);

char *get_permissions_from_line(char *line);

long get_end_address_from_maps_line(char *line);

long get_start_address_from_maps_line(char *line);

int copy_and_run_payload(int pid, unsigned long target_addr, char * payload, int payload_length);

int inject_payload(int pid, long target_addr, char * payload, size_t payload_length);
