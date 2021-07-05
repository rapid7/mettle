#include "extension.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <string.h>
#include <stdlib.h>

#include "lua.h"

char *str_output = NULL;

/*
 * Override 'print' so the extension won't crash
 * Thanks @timwr for the link: https://gist.github.com/5at/3671566
 */
static int print_to_framework_side(lua_State *lua) {
	int nargs = lua_gettop(lua);
	for (int i = 0; i < nargs; i++) {
		const char *str = lua_tostring(lua, i);

        // Extend buffer
		str_output = realloc(str_output, strlen(str_output) + strlen(str));
        if (str_output == NULL) {
            continue;
        }

        str_output = strcat(str_output, str); // Add output
	}

	return 0;
}

static const struct luaL_Reg print_overrider [] = {
	{"print", print_to_framework_side},
	{NULL, NULL} // End marker
};

/*
 * Execute the code supplied (via TLV packet) string
 */
static struct tlv_packet *request_execute_code(struct tlv_handler_ctx *ctx)
{
	lua_State *lua;

	lua = luaL_newstate();
	luaL_openlibs(lua);

	lua_getglobal(lua, "_G");
	luaL_setfuncs(lua, print_overrider, 0);
	lua_pop(lua, 1);

	int tlv_result = TLV_RESULT_FAILURE; // By default
	struct tlv_packet *r = tlv_packet_response(ctx);

	char *execute_me = tlv_packet_get_str(ctx->req, TLV_TYPE_LUA_CODE);
	if (luaL_dostring(lua, execute_me) == 0) {
		tlv_result = TLV_RESULT_SUCCESS;
	}

	// We could use lua_gettop and lua_tostring to send the
	// return values to MSF.
	// It might be interesting to expose internal functions to the lua
	// script(s) so one could use the extension to write lua agents.

	lua_close(lua);

    if (str_output != NULL) {
        // Something was printed
        r = tlv_packet_add_str(r, TLV_TYPE_STRING, str_output);
    } else {
        r = tlv_packet_add_str(r, TLV_TYPE_STRING, "null");
    }

    free(str_output); // Filled whenever lua prints something

	r = tlv_packet_add_result(r, tlv_result);
	return r;
}


/*
 * Lua module starts here!
 */
int main(void)
{
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

	return 0;
}
