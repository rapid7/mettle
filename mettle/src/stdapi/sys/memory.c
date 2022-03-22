#include <stdio.h>
#include <regex.h>
#include <fnmatch.h>
#include <ctype.h>
#include <fnmatch.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"
#include "command_ids.h"
#include "memory.h"

#define NEEDLES_MAX 5
#define MAX_ADDR_DATA 350

struct addr_range
{
    unsigned long start;
    unsigned long end;
    struct addr_range *next;
};

struct tlv_packet *mem_search(struct tlv_handler_ctx *ctx)
{
    unsigned int pid;
    struct tlv_packet *p = NULL;

    if(tlv_packet_get_u32(ctx->req, TLV_TYPE_PID, &pid) == -1)
    {
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    struct tlv_iterator i = {
        .packet = ctx->req,
        .value_type = TLV_TYPE_MEM_SEARCH_NEEDLE
    };

    char *needle;
    uint8_t needles_len = 0;
    char *needles[ NEEDLES_MAX ];
    while((needle = tlv_packet_iterate_str(&i)))
    {
        needles[ needles_len ] = malloc(strlen(needle) + 1);
        needles_len++;
    }

    struct addr_range *ranges = parse_maps_file(pid);

    for(uint8_t i = 0; i < needles_len; i++)
    {
        free(needles[i]);
    }

    return NULL;
}

/*
 *  This will open /proc/PID/maps and search for
 *  the start and end addresses for all readable sections
 */
struct addr_range *parse_maps_file(pid_t pid)
{
    char pid_str[8];
    sprintf(pid_str, "%d", pid);
    int path_len = strlen("/proc/") + strlen(pid_str) + strlen("/maps") + 1;

    char maps_path[path_len];
    snprintf(maps_path, path_len - 1, "/proc/%s/maps", pid_str);
    log_debug("Opening maps file: %s\n", maps_path);

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
    regcomp(&regex, "r[w|-][x|-][p|-]", REG_EXTENDED | REG_NOSUB);
    while(fgets(line, MAX_ADDR_DATA, fp) != NULL)
    {
        if(regexec(&regex, line, 0, NULL, 0) == 0)
        {
            char *addr_begin = strtok(line, "-");
            char *addr_end = strtok(NULL, "- ");
            struct addr_range *range = malloc(sizeof(struct addr_range));
            range->start = strtoul(addr_begin, NULL, 16);
            range->end = strtoul(addr_end, NULL, 16);

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

void sys_memory_register_handlers(struct mettle *m)
{
    struct channelmgr *cm = mettle_get_channelmgr(m);
    struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

    tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_MEM_SEARCH, mem_search, m);
}
