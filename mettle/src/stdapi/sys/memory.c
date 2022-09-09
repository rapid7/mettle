#ifdef __linux__

#include <stdio.h>
#include <regex.h>
#include <fnmatch.h>
#include <fnmatch.h>
#include <ctype.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"
#include "command_ids.h"
#include "memory.h"

#define NEEDLES_MAX 5
#define MAX_ADDR_DATA 500
#define MATCH_LEN_MAX 250
#define MATCH_PER_NEEDLE_MAX 5

#define MAX_STRINGS 350
#define MIN_SEARCH_LEN 5

struct tlv_packet *mem_read(struct tlv_handler_ctx *ctx)
{
	uint64_t pid;
	uint32_t size;
	uint64_t start_addr;
	struct tlv_packet *p = NULL;

	if(tlv_packet_get_u64(ctx->req, TLV_TYPE_HANDLE, &pid) == -1)
	{
		log_debug("Pid was not retrieved.\n");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	if(tlv_packet_get_u64(ctx->req, TLV_TYPE_BASE_ADDRESS, &start_addr) == -1)
	{
		log_debug("Failed to retrieve the start address.\n");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	if(tlv_packet_get_u32(ctx->req, TLV_TYPE_LENGTH, &size) == -1)
	{
		log_debug("Failed to retrieve size to search.\n");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	if(size <= 0)
	{
		size = MATCH_LEN_MAX;
	}

	char *read_str = NULL;
	char mem_path[PATH_MAX];
	snprintf(mem_path, PATH_MAX, "/proc/%zu/mem", (size_t)pid);
	log_debug("Path to read from: %s\n", mem_path);

	FILE *fp = fopen(mem_path, "r");
	if(fp == NULL)
	{
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	unsigned char buf[size];
	fseeko(fp, start_addr, SEEK_SET);
	size_t res = fread(buf, 1, size, fp);
	if(res == 0)
	{
		fclose(fp);
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	fclose(fp);

	p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	p = tlv_packet_add_raw(p, TLV_TYPE_PROCESS_MEMORY, buf, size);

	return p;
}

struct tlv_packet *mem_search(struct tlv_handler_ctx *ctx)
{
	uint32_t pid;
	uint32_t match_len;
	uint32_t min_search_len;
	struct tlv_packet *p = NULL;

	if(tlv_packet_get_u32(ctx->req, TLV_TYPE_PID, &pid) == -1)
	{
		log_debug("Failed to retrieve PID\n");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	if(tlv_packet_get_u32(ctx->req, TLV_TYPE_MEMORY_SEARCH_MATCH_LEN, &match_len) == -1)
	{
		log_debug("Failed to retrieve match length\n");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	if(tlv_packet_get_u32(ctx->req, TLV_TYPE_UINT, &min_search_len) == -1)
	{
		log_debug("Using default minimum for search\n");
		min_search_len = MIN_SEARCH_LEN;
	}

	if(match_len > MATCH_LEN_MAX)
	{
		match_len = MATCH_LEN_MAX;
	}

	log_debug("Searching PID: %zu\n", (size_t) pid);
	struct addr_range *ranges = parse_maps_file(pid);
	if(ranges == NULL)
	{
		log_debug("Failed to retrieve ranges\n");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct tlv_iterator i = {
		.packet = ctx->req,
		.value_type = TLV_TYPE_MEMORY_SEARCH_NEEDLE
	};

	char *needle;
	uint8_t needles_len = 0;
	char *needles[ NEEDLES_MAX ];
	while((needle = tlv_packet_iterate_str(&i)))
	{
		needles[ needles_len ] = malloc(strlen(needle) + 1);
		strncpy(needles[ needles_len ], needle, strlen(needle) + 1);
		needles_len++;
	}

	int match_num = 0;
	struct match_result *matches = search_mem_sections(pid, min_search_len, ranges, needles, needles_len, &match_num);
	if(matches == NULL || match_num == 0)
	{
		log_debug("Matches var is NULL\n");
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		goto out;
	}

	struct tlv_packet *res = NULL;
	struct match_result *prev = NULL;
	p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	log_debug("Number of matches: %d\n", match_num);
	for(int i = 0; i < match_num; i++)
	{
		uint64_t sect_len = 0;
		uint64_t start_addr = 0;
		uint64_t match_addr = 0;

		int match_str_len = strlen((matches + i)->match_str) + 1;
		char match_string[match_str_len];
		strncpy(match_string, (matches + i)->match_str, match_str_len);

		res = tlv_packet_new(TLV_TYPE_MEMORY_SEARCH_RESULTS, 0);
		res = tlv_packet_add_str(res, TLV_TYPE_MEMORY_SEARCH_MATCH_STR, match_string);

		memcpy(&start_addr, &(matches + i)->section_start, sizeof(uint64_t));
		memcpy(&sect_len, &(matches + i)->section_len, sizeof(uint64_t));
		memcpy(&match_addr, &(matches + i)->match_offset, sizeof(uint64_t));

		res = tlv_packet_add_u64(res, TLV_TYPE_MEMORY_SEARCH_SECT_LEN, sect_len);
		res = tlv_packet_add_u64(res, TLV_TYPE_MEMORY_SEARCH_START_ADDR, start_addr);
		res = tlv_packet_add_u64(res, TLV_TYPE_MEMORY_SEARCH_MATCH_ADDR, match_addr);

		p = tlv_packet_add_child(p, res);
	}

	for(int i = 0; i < match_num; i++)
	{
		free((matches + i)->match_str);
	}

	free(matches);

out:
	for(uint8_t i = 0; i < needles_len; i++)
	{
		free(needles[i]);
	}

	struct addr_range *range = ranges;
	while(range != NULL)
	{
		struct addr_range *curr = range;
		range = range->next;
		free(curr);
	}

	return p;
}

char *get_readable_str(FILE *fp, uint32_t min_len, uint64_t *start_addr, uint64_t end_addr)
{
	int curr_index = 0;
	uint32_t curr_char;
	uint64_t index = 0;
	uint32_t max_str_len = MATCH_LEN_MAX - 1;
	char *printable = malloc(MATCH_LEN_MAX);
	memset(printable, 0, MATCH_LEN_MAX);

	uint64_t sect_len = end_addr - *start_addr;
	while(index < sect_len)
	{
		if((curr_char = fgetc(fp)) == EOF)
		{
			*start_addr += index;
			return NULL;
		}
		if(isprint(curr_char))
		{
			printable[curr_index] = curr_char;
			curr_index++;
		}
		else
		{
			int str_len = strlen(printable);

			// don't collect strings smaller than min size
			if(str_len < min_len && str_len > 0)
			{
				curr_index = 0;
				memset(printable, 0, str_len);
			}
			else if(str_len > 0)
			{
				*start_addr += index;
				return printable;
			}
		}

		if(curr_index > max_str_len)
		{
			max_str_len += MATCH_LEN_MAX;
			int str_len = strlen(printable);
			int new_len = str_len + MATCH_LEN_MAX;
			printable = realloc(printable, str_len + MATCH_LEN_MAX);
			memset(printable + str_len, 0, MATCH_LEN_MAX);
		}

		index++;
	}

	*start_addr += index;
	if(strlen(printable) == 0)
	{
		return NULL;
	}

	return printable;
}

/*
 * checks a string against one or more compiled regexes and returns those that match
 */
regmatch_t *find_matches(char *str, struct needle_info *needle_arr, int needle_amt, int *match_num)
{
	int exec_ret;
	regmatch_t reg_matches[needle_amt * MATCH_PER_NEEDLE_MAX]; // every needle has set number of possible matches

	int match_index = 0;
	regmatch_t *matches = malloc(sizeof(regmatch_t) * (needle_amt * MATCH_PER_NEEDLE_MAX)); // matches to return
	memset(matches, 0, sizeof(regmatch_t) * needle_amt * MATCH_PER_NEEDLE_MAX);
	for(int i = 0; i < needle_amt; i++)
	{
		// make sure that the regex is a compiled regex
		if(needle_arr[i].compiled == 1)
		{
			exec_ret = regexec(&needle_arr[i].preg, str, MATCH_PER_NEEDLE_MAX, &reg_matches[i * MATCH_PER_NEEDLE_MAX], 0);
			if(exec_ret == 0)
			{
				for(int j = match_index; j < match_index + MATCH_PER_NEEDLE_MAX; j++)
				{
					if(reg_matches[j].rm_so == -1 && reg_matches[j].rm_eo == -1)
					{
						continue;
					}

					memcpy(matches + *match_num, &reg_matches[j], sizeof(regmatch_t));
					(*match_num)++;
				}

			}

			match_index += MATCH_PER_NEEDLE_MAX;
		}
	}

	if(*match_num == 0)
	{
		return NULL;
	}

	return matches;
}

struct match_result *search_mem_sections(pid_t pid, uint32_t min_len, struct addr_range *ranges, char *needles[], int needle_amt, int *match_len)
{
	char *read_str = NULL;
	char mem_path[PATH_MAX];
	snprintf(mem_path, PATH_MAX, "/proc/%zu/mem", (size_t)pid);

	struct addr_range *current = NULL, *first = NULL;
	FILE *fp = fopen(mem_path, "r");
	if(fp == NULL)
	{
		return NULL;
	}

	int res_size = 0;
	regmatch_t *matches;
	current = first = ranges;

	int results_len = needle_amt * MATCH_PER_NEEDLE_MAX;
	struct match_result *results = malloc(sizeof(struct match_result) * needle_amt * MATCH_PER_NEEDLE_MAX);
	struct match_result *first_res = results;
	memset(results, 0, sizeof(struct match_result) * needle_amt * MATCH_PER_NEEDLE_MAX);

	if(results == NULL)
	{
		fclose(fp);
		return NULL;
	}

	// compile a version of each needle to test against each string
	regex_t regex_arr[needle_amt];
	struct needle_info needle_arr[needle_amt];
	for(int i = 0; i < needle_amt; i++)
	{
		needle_arr[i].needle = needles[i];
		if(regcomp(&needle_arr[i].preg, needles[i], REG_EXTENDED) != 0)
		{
			needle_arr[i].compiled = 0;
		}
		else
		{
			needle_arr[i].compiled = 1;
		}
	}

	int curr_matches = 0;
	uint64_t curr_addr = current->start;
	while(current->next != NULL)
	{
		fseeko(fp, curr_addr, SEEK_SET);
		read_str = get_readable_str(fp, min_len, &curr_addr, current->end);
		if(read_str == NULL)
		{
			current = current->next;
			curr_addr = current->start;
			continue;
		}
		else if((matches = find_matches(read_str, needle_arr, needle_amt, &curr_matches)) != NULL)
		{
			if(res_size + curr_matches >= results_len)
			{
				struct match_result *new_res = realloc(first_res, sizeof(struct match_result) * results_len * 2);
				if(new_res == NULL)
				{
					break;
				}

				memset(new_res + res_size, 0, results_len);
				first_res = new_res;
				results_len *= 2;
				results = first_res + res_size;
			}

			int match_num = add_matches(read_str, &results, curr_addr, current->start, current->end - current->start, matches);
			curr_matches = 0;
			res_size += match_num;
			results += match_num;
		}

		free(read_str);
		if(curr_addr >= current->end)
		{
			current = current->next;
			curr_addr = current->start;
		}
	}

	fclose(fp);
	*match_len = res_size;
	for(int j = 0; j < needle_amt; j++)
	{
		if(needle_arr[j].compiled)
		{
			regfree(&needle_arr[j].preg);
		}
	}

	if(res_size == 0)
	{
		return NULL;
	}

	return first_res;
}

int add_matches(char *full_str, struct match_result **results, uint64_t match_offset, uint64_t sect_start, uint64_t sect_len, regmatch_t *matches)
{
	int index = 0;
	regmatch_t *prev = NULL;
	regmatch_t *start = matches;
	struct match_result *curr_result = *results;

	do
	{
		if(start->rm_so != start->rm_eo)
		{
			int match_len = start->rm_eo - start->rm_so + 1;
			curr_result->match_str = malloc(match_len);
			if(curr_result->match_str == NULL)
			{
				log_debug("Allocation for matches failed");
				prev = start;
				start++;
				free(prev);
				continue;
			}

			/*
			 * save the start address and length of memory location match was found in,
			 * save the offset of the match, and save the matched string
			 */
			strncpy(curr_result->match_str, full_str + start->rm_so, match_len);
			curr_result->section_start = sect_start;
			curr_result->section_len = sect_len;
			curr_result->match_offset = match_offset + start->rm_so;
			curr_result++;
			index++;
		}

		prev = start;
		start++;
		free(prev);
	} while(start != NULL);

	return index;
}

/*
 *  This will open /proc/PID/maps and search for
 *  the start and end addresses for all readable sections
 *  that are not file-backed
 */
struct addr_range *parse_maps_file(pid_t pid)
{
	char pid_str[8];
	sprintf(pid_str, "%d", pid);
	int path_len = strlen("/proc/") + strlen(pid_str) + strlen("/maps") + 1;

	char maps_path[path_len];
	snprintf(maps_path, path_len, "/proc/%s/maps", pid_str);
	log_debug("Maps path in parse_maps_file(): %s\n", maps_path);

	FILE *fp = fopen(maps_path, "r");
	if(fp == NULL)
	{
		log_debug("Could not open maps file.\n");
		return NULL;
	}

	regex_t regex;
	int index = 0;
	char *line = malloc(MAX_ADDR_DATA);
	struct addr_range *first = NULL, *current = NULL;
	regcomp(&regex, "rw[x|-][p|-]", REG_EXTENDED | REG_NOSUB);
	while(fgets(line, MAX_ADDR_DATA, fp) != NULL)
	{
		int len = strlen(line);
		if(regexec(&regex, line, 0, NULL, 0) == 0)
		{
			char *addr_begin = strtok(line, "-");
			char *addr_end = strtok(NULL, "- ");
			struct addr_range *range = malloc(sizeof(struct addr_range));
			if(range == NULL)
			{
				fclose(fp);
				free(line);
				regfree(&regex);
				return first;
			}

			range->start = strtoll(addr_begin, NULL, 16);
			range->end = strtoll(addr_end, NULL, 16);

			if(index == 0)
			{
				first = current = range;
				first->next = NULL;
			}
			else
			{
				current->next = range;
				current = range;
				current->next = NULL;

				if(index == 1)
				{
					first->next = current;
				}
			}

			index++;
		}

		memset(line, 0, MAX_ADDR_DATA);
	}

	fclose(fp);
	free(line);
	regfree(&regex);

	return first;
}
#endif

void sys_memory_register_handlers(struct mettle *m)
{
#ifdef __linux__
	struct channelmgr *cm = mettle_get_channelmgr(m);
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_SEARCH, mem_search, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_READ, mem_read, m);
#endif
}

