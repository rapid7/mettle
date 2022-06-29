#ifndef _STDAPI_MEMORY_H
#define _STDAPI_MEMORY_H

#ifdef __linux__

struct addr_range
{
	uint64_t start;
	uint64_t end;
	struct addr_range *next;
};

struct match_result
{
	char *match_str;
	uint64_t section_len;
	uint64_t section_start;
	uint64_t match_offset;
};

struct needle_info
{
	char *needle;
	regex_t preg;
	uint8_t compiled;
};

struct tlv_packet *mem_search(struct tlv_handler_ctx *ctx);
struct addr_range *parse_maps_file(pid_t pid);
struct match_result *search_mem_sections(pid_t pid, uint32_t min_len, struct addr_range *ranges, char *needles[], int needle_amt, int *match_len);
char *get_readable_str(FILE *fp, uint32_t min_len, uint64_t *start_addr, uint64_t end_addr);
regmatch_t *find_matches(char *str, struct needle_info *needle_arr, int needle_amt, int *match_num);
int add_matches(char *full_str, struct match_result **results, uint64_t match_offset, uint64_t sect_start, uint64_t sect_len, regmatch_t *matches);

#endif

#endif
