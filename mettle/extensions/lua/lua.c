#include "extension.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "lua.h"

lua_State *lua;

/*
 * Execute the supplied (via TLV packet) string
 */
static struct tlv_packet *request_execute_code(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE; // By default
	struct tlv_packet *r = tlv_packet_response(ctx);

	char *execute_me = tlv_packet_get_str(ctx->req, TLV_TYPE_LUA_CODE);
	if (luaL_dostring(lua, execute_me) == 0) {
		r = TLV_RESULT_SUCCESS;
	}

	r = tlv_packet_add_result(r, tlv_result);
	return r;
}


/*
 * Sniffer module starts here!
 */
int main(void)
{
	lua = luaL_newstate();
	luaL_openlibs(lua);

#ifdef DEBUG
	extension_log_to_mettle(EXTENSION_LOG_LEVEL_INFO);
#endif

	struct extension *e = extension();

	// Register the commands and assocaited handlers this extension provides.
	extension_add_handler(e, "lua_dostring", request_execute_code, NULL);

	// Ready to go!
	extension_start(e);

	// On the way out now, let's wind things down...
	extension_free(e);
	lua_close(lua);

	return 0;
}
