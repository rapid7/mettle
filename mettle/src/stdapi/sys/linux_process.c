#include <mettle.h>
#include <sys/ioctl.h>

#include "log.h"
#include "tlv.h"
#include "command_ids.h"
#include "process.h"

struct tlv_packet *
sys_process_set_term_size(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);

	uint32_t rows, columns;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_TERMINAL_ROWS, &rows);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_TERMINAL_COLUMNS, &columns);

	struct process *p = channel_get_ctx(c);
	struct winsize ws = {
			.ws_row = rows,
			.ws_col = columns
	};
	printf ("lines %d\n", ws.ws_row);
	printf ("columns %d\n", ws.ws_col);
	ioctl(process_get_in_fd(p), TIOCSWINSZ, &ws);
	printf ("lines %d\n", ws.ws_row);
	printf ("columns %d\n", ws.ws_col);
	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

}
