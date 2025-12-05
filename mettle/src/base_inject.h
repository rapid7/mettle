#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>

//temporarly using PTRACE
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define SIZE_OF_ADDRESS 12


int is_root();

int inject_procfs();

int migrate(int pid, char * migrate_stub, size_t migrate_stub_length, char * payload, size_t payload_length);
int get_process_sections();

unsigned long find_codecave();

void read_process_memory();

int is_readable(char * line);

char *get_permissions_from_line(char *line);

long get_end_address_from_maps_line(char *line);

long get_start_address_from_maps_line(char *line);

int copy_and_run_payload(int pid, unsigned long target_addr, char * payload, int payload_length);

int inject_payload(int pid, long target_addr, char * payload, size_t payload_length);
