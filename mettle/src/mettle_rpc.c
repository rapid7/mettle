#include <string.h>

#include "json.h"
#include "log.h"
#include "mettle.h"
#include "network_server.h"
#include "utlist.h"

struct mettle_rpc {
	struct mettle *m;
	int running;
	struct network_server *ns;
	struct json_rpc *jrpc;
	struct mettle_rpc_conn {
		struct mettle_rpc *mrpc;
		struct json_tokener *tok;
		struct bufferev *bev;
		struct mettle_rpc_conn *next;
	} *conns;
};

static struct mettle_rpc_conn * get_conn(struct mettle_rpc *mrpc,
	struct bufferev *bev)
{
	struct mettle_rpc_conn *conn;
	LL_FOREACH(mrpc->conns, conn) {
		if (conn->bev == bev) {
			return conn;
		}
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		return NULL;
	}

	conn->mrpc = mrpc;
	conn->bev = bev;
	conn->tok = json_tokener_new();
	if (!conn->tok) {
		free(conn);
		return NULL;
	}

	LL_APPEND(mrpc->conns, conn);
	return conn;
}

static void handle_rpc(struct json_object *obj, void *arg)
{
	struct mettle_rpc_conn *conn = arg;

	struct json_object *response = NULL;
	if (obj != NULL) {
		response = json_rpc_process(conn->mrpc->jrpc, obj);
	} else {
		enum json_tokener_error rc = json_tokener_get_error(conn->tok);
		if (rc != json_tokener_continue) {
			response = json_rpc_gen_error(conn->mrpc->jrpc,
				NULL, JSON_RPC_PARSE_ERROR, "Parse error");
			json_tokener_reset(conn->tok);
		}
	}
	if (response) {
		const char *str = json_object_to_json_string_ext(response, 0);
		bufferev_write(conn->bev, str, strlen(str));
		json_object_put(response);
	}
	json_object_put(obj);
}

static void read_cb(struct bufferev *bev, void *arg)
{
	struct mettle_rpc *mrpc = arg;
	struct mettle_rpc_conn *conn = get_conn(mrpc, bev);
	if (conn) {
		json_read_bufferev_cb(bev, conn->tok, handle_rpc, conn);
	} else {
		bufferev_free(bev);
	}
}

static void event_cb(struct bufferev *bev, int event, void *arg)
{
	struct mettle_rpc *mrpc = arg;

	if (event & (BEV_EOF|BEV_ERROR)) {
		struct mettle_rpc_conn *conn = get_conn(mrpc, bev);
		if (conn) {
			LL_DELETE(mrpc->conns, conn);
			json_tokener_free(conn->tok);
			free(conn);
		}
	}
}

void mettle_rpc_free(struct mettle_rpc *mrpc)
{
	if (mrpc) {
		if (mrpc->jrpc) {
			json_rpc_free(mrpc->jrpc);
		}
		if (mrpc->ns) {
			network_server_free(mrpc->ns);
		}
		free(mrpc);
	}
}

struct mettle_rpc * mettle_rpc_new(struct mettle *m)
{
	struct mettle_rpc *mrpc = calloc(1, sizeof(*mrpc));
	if (mrpc == NULL) {
		return NULL;
	}

	mrpc->m = m;

	mrpc->jrpc = json_rpc_new(JSON_RPC_CHECK_VERSION);
	if (mrpc->jrpc == NULL) {
		goto err;
	}

	mrpc->ns = network_server_new(mettle_get_loop(m));
	char *host = "127.0.0.1";
	uint16_t port = 1337;
	if (network_server_listen_tcp(mrpc->ns, host, port) == -1) {
		log_info("failed to listen on %s:%d", host, port);
		goto err;
	}

	return mrpc;

err:
	mettle_rpc_free(mrpc);
	return NULL;
}
