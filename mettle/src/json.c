#include "log.h"
#include "json.h"
#include "utlist.h"

#include <errno.h>
#include <inttypes.h>

struct json_object *json_read_file(const char *filename)
{
	struct json_object *obj = NULL;
	FILE *file = fopen(filename, "r");
	struct json_tokener *tok = json_tokener_new();

	if (!file || !tok) {
		goto out;
	}

	char buf[4096];
	ssize_t buf_len;
	enum json_tokener_error rc = json_tokener_continue;

	do  {
		buf_len = fread(buf, 1, sizeof(buf), file);
		if (buf_len > 0) {
			obj = json_tokener_parse_ex(tok, buf, buf_len);
			rc = json_tokener_get_error(tok);
		}
	} while (buf_len > 0 && rc == json_tokener_continue);

	if (rc != json_tokener_success) {
		log_error("JSON parse error: %s", json_tokener_error_desc(rc));
	}

out:
	if (tok) {
		json_tokener_free(tok);
	}
	if (file) {
		fclose(file);
	}
	return obj;
}

struct json_object * json_read_buf(const void *buf, ssize_t buf_len)
{
	struct json_tokener *tok = json_tokener_new();
	struct json_object *obj = json_tokener_parse_ex(tok, buf, buf_len);
	if (!obj) {
		enum json_tokener_error rc = json_tokener_get_error(tok);
		log_error("JSON parse error: %s", json_tokener_error_desc(rc));
	}
	json_tokener_free(tok);
	return obj;
}

struct json_object *json_read_bufferev(struct bufferev *bev, struct json_tokener *tok)
{
	char buf[4096];
	size_t buf_len;
	struct json_object *obj = NULL;
	enum json_tokener_error rc = json_tokener_continue;
	do {
		buf_len = bufferev_read(bev, buf, sizeof(buf));
		if (buf_len) {
			obj = json_tokener_parse_ex(tok, buf, buf_len);
			rc = json_tokener_get_error(tok);
		}
	} while (buf_len && rc == json_tokener_continue);

	return obj;
}

void json_read_bufferev_cb(struct bufferev *bev, struct json_tokener *tok,
		json_read_cb cb, void *arg)
{
	char buf[4096];
	size_t buf_len, last_read = 0;
	struct json_object *obj = NULL;
	enum json_tokener_error rc = json_tokener_continue;
	do {
		buf_len = bufferev_read(bev, buf, sizeof(buf));
		if (buf_len) {
			last_read = buf_len;
			obj = json_tokener_parse_ex(tok, buf, buf_len);
			rc = json_tokener_get_error(tok);
			if (obj) {
				cb(obj, arg);
			}
		}
	} while (buf_len && rc == json_tokener_continue);

	if (tok->char_offset < last_read) {
		size_t offset = tok->char_offset;
		while ((obj = json_tokener_parse_ex(tok, buf + offset, last_read - offset))) {
			offset += tok->char_offset;
			cb(obj, arg);
		}
	}
}

void json_read_buffer_queue_cb(struct buffer_queue *queue, struct json_tokener *tok,
		json_read_cb cb, void *arg)
{
	void *buf;
	size_t buf_len, last_read = 0;
	struct json_object *obj = NULL;
	enum json_tokener_error rc = json_tokener_continue;
	do {
		buf_len = buffer_queue_remove_all(queue, &buf);
		if (buf_len) {
			last_read = buf_len;
			obj = json_tokener_parse_ex(tok, buf, buf_len);
			rc = json_tokener_get_error(tok);
			if (obj) {
				cb(obj, arg);
			}
			free(buf);
		}
	} while (buf_len && rc == json_tokener_continue);

	if (tok->char_offset < last_read) {
		size_t offset = tok->char_offset;
		while ((obj = json_tokener_parse_ex(tok, buf + offset, last_read - offset))) {
			offset += tok->char_offset;
			cb(obj, arg);
		}
	}
}

int json_add_str(struct json_object *json, const char *key, const char *val)
{
	if (val) {
		struct json_object *obj = json_object_new_string(val);
		if (obj) {
			json_object_object_add(json, key, obj);
			return 0;
		}
	}
	return -1;
}

int json_add_str_fmt(struct json_object *json, const char *key, const char *format, ...)
{
	char *buf = NULL;
	va_list args;
	va_start(args, format);
	if (vasprintf(&buf, format, args) == -1) {
		buf = NULL;
	}
	va_end(args);

	int rc = json_add_str(json, key, buf);
	free(buf);
	return rc;
}

int json_add_int32(struct json_object *json, const char *key, int32_t val)
{
	struct json_object *obj = json_object_new_int(val);
	if (obj) {
		json_object_object_add(json, key, obj);
		return 0;
	}
	return -1;
}

int json_add_int64(struct json_object *json, const char *key, int64_t val)
{
	struct json_object *obj = json_object_new_int64(val);
	if (obj) {
		json_object_object_add(json, key, obj);
		return 0;
	}
	return -1;
}

int json_add_double(struct json_object *json, const char *key, double val)
{
	struct json_object *obj = json_object_new_double(val);
	if (obj) {
		json_object_object_add(json, key, obj);
		return 0;
	}
	return -1;
}

int json_add_bool(struct json_object *json, const char *key, bool val)
{
	struct json_object *obj = json_object_new_boolean(val);
	if (obj) {
		json_object_object_add(json, key, obj);
		return 0;
	}
	return -1;
}

int json_get_str(json_object *json, const char *key, const char **dst)
{
	struct json_object *obj = json_object_object_get(json, key);
	if (obj) {
		*dst = json_object_get_string(obj);
	}
	return *dst ? 0 : -1;
}

int json_get_str_def(json_object *json, const char *key, const char **dst, const char *def)
{
	struct json_object *obj = json_object_object_get(json, key);
	if (obj) {
		*dst = json_object_get_string(obj);
	}
	if (*dst == NULL) {
		*dst = def;
	}
	return *dst ? 0 : -1;
}

int json_get_int32(json_object *json, const char *key, int32_t *dst)
{
	struct json_object *obj = json_object_object_get(json, key);
	if (obj) {
		*dst = json_object_get_int(obj);
		if (errno != EINVAL) {
			return 0;
		}
	}
	return -1;
}

int json_get_int64(json_object *json, const char *key, int64_t *dst)
{
	struct json_object *obj = json_object_object_get(json, key);
	if (obj) {
		*dst = json_object_get_int64(obj);
		if (errno != EINVAL) {
			return 0;
		}
	}
	return -1;
}

int json_get_double(json_object *json, const char *key, double *dst)
{
	struct json_object *obj = json_object_object_get(json, key);
	if (obj) {
		*dst = json_object_get_double(obj);
		if (errno != EINVAL) {
			return 0;
		}
	}
	return -1;
}

int json_get_bool(json_object *json, const char *key, bool *dst)
{
	struct json_object *obj = json_object_object_get(json, key);
	if (obj) {
		*dst = json_object_get_boolean(obj);
		if (errno != EINVAL) {
			return 0;
		}
	}
	return -1;
}

struct json_rpc {
	int flags;
	struct json_method {
		char *name;
		char **params;
		int num_params;
		json_method_cb cb;
		void *arg;
	} *methods;
	int num_methods;

	int64_t next_request_id;
	struct json_request {
		json_result_cb cb;
		void *arg;
		int64_t id;
		struct json_request *next;
	} *requests;
};

struct json_rpc * json_rpc_new(int flags)
{
	struct json_rpc *jrpc = calloc(1, sizeof(*jrpc));
	if (jrpc) {
		jrpc->flags = flags;
	}
	return jrpc;
}

void json_rpc_free(struct json_rpc *jrpc)
{
	if (jrpc) {
		for (int i = 0; i < jrpc->num_methods; i++) {
			free(jrpc->methods[i].params);
		}
		free(jrpc->methods);
		struct json_request *req, *tmp;
		LL_FOREACH_SAFE(jrpc->requests, req, tmp) {
			free(req);
		}
	}
}

static struct json_method *find_method(struct json_rpc *jrpc,
	const char *method_name)
{
	for (int i = 0; i < jrpc->num_methods; i++) {
		if (strcmp(method_name, jrpc->methods[i].name) == 0) {
			return &jrpc->methods[i];
		}
	}
	return NULL;
}

int json_rpc_register_method(struct json_rpc *jrpc,
	const char *method_name, const char *params, json_method_cb cb, void *arg)
{
	struct json_method *m = find_method(jrpc, method_name);
	if (m || !cb) {
		return -1;
	}
	jrpc->methods = reallocarray(jrpc->methods,
		jrpc->num_methods + 1, sizeof(struct json_method));
	m = &jrpc->methods[jrpc->num_methods];
	memset(m, 0, sizeof(struct json_method));
	m->name = strdup(method_name);
	m->cb = cb;
	m->arg = arg;
	if (params) {
		char *token, *string, *tofree;
		tofree = string = strdup(params);
		while ((token = strsep(&string, ",")) != NULL) {
			m->params = reallocarray(m->params,
				m->num_params + 1, sizeof(char *));
			m->params[m->num_params] = m->params[m->num_params];
			m->num_params++;
		}
		free(tofree);
	}
	jrpc->num_methods++;
	return 0;
}

static struct json_request * json_rpc_find_request(struct json_rpc *jrpc,
	int64_t id)
{
	if (jrpc->requests) {
		struct json_request *r;
		LL_FOREACH(jrpc->requests, r) {
			if (r->id == id) {
				return r;
			}
		}
	}
	return NULL;
}

int json_rpc_register_result_cb(struct json_rpc *jrpc,
	int64_t id, json_result_cb cb, void *arg)
{
	struct json_request *r = json_rpc_find_request(jrpc, id);
	if (r || cb == NULL) {
		return -1;
	}
	r = calloc(1, sizeof(*r));
	if (r) {
		r->id = id;
		r->cb = cb;
		r->arg = arg;
		LL_PREPEND(jrpc->requests, r);
	}
	return 0;
}

static bool is_jsonrpc(struct json_rpc *jrpc, struct json_object *json)
{
	const char *version;
	return !(jrpc->flags & JSON_RPC_CHECK_VERSION) ||
		(json_get_str(json, "jsonrpc", &version) == 0 && strcmp(version, "2.0") == 0);
}

static struct json_object *json_rpc_obj_get(struct json_rpc *jrpc)
{
	struct json_object *obj = json_object_new_object();
	if (obj && (jrpc->flags & JSON_RPC_CHECK_VERSION)) {
		json_add_str(obj, "jsonrpc", "2.0");
	}
	return obj;
}

struct json_object * json_rpc_gen_error(struct json_rpc *jrpc,
	struct json_object *id, int code, const char *message)
{
	struct json_object *obj = id ? json_rpc_obj_get(jrpc) : NULL;
	if (obj) {
		json_object_get(id);
		json_object_object_add(obj, "id", id);
		struct json_object *error = json_object_new_object();
		json_add_int32(error, "code", code);
		json_add_str(error, "message", message);
		json_object_object_add(obj, "error", error);
	}
	return obj;
}

struct json_object * json_rpc_gen_method_call(struct json_rpc *jrpc,
	const char *method_name, int64_t *id, struct json_object *params)
{
	struct json_object *obj = json_rpc_obj_get(jrpc);
	*id = jrpc->next_request_id++;
	if (obj) {
		json_add_str(obj, "method", method_name);
		json_add_int64(obj, "id", *id);
		if (params) {
			json_object_object_add(obj, "params", params);
		}
	}
	return obj;
}

struct json_object * json_rpc_gen_notification(struct json_rpc *jrpc,
	const char *method_name, struct json_object *params)
{
	struct json_object *obj = json_rpc_obj_get(jrpc);
	if (obj) {
		json_add_str(obj, "method", method_name);
		if (params) {
			json_object_object_add(obj, "params", params);
		}
	}
	return obj;
}

struct json_object * json_rpc_gen_result_json(struct json_rpc *jrpc,
	struct json_object *id, json_object *result)
{
	struct json_object *obj = id ? json_rpc_obj_get(jrpc) : NULL;
	if (obj) {
		json_object_get(id);
		json_object_object_add(obj, "id", id);
		json_object_object_add(obj, "result", result);
	}
	return obj;
}

struct json_object * json_rpc_gen_result_str(struct json_rpc *jrpc,
	struct json_object *id, const char *result)
{
	struct json_object *obj = id ? json_rpc_obj_get(jrpc) : NULL;
	if (obj) {
		json_object_get(id);
		json_object_object_add(obj, "id", id);
		json_add_str(obj, "result", result);
	}
	return obj;
}

struct json_object * json_rpc_gen_result_int32(struct json_rpc *jrpc,
    struct json_object *id, int32_t result)
{
    struct json_object *obj = id ? json_rpc_obj_get(jrpc) : NULL;
    if (obj) {
        json_object_get(id);
        json_object_object_add(obj, "id", id);
        json_add_int32(obj, "result", result);
    }
    return obj;
}

struct json_object * json_rpc_gen_result_int64(struct json_rpc *jrpc,
    struct json_object *id, int64_t result)
{
    struct json_object *obj = id ? json_rpc_obj_get(jrpc) : NULL;
    if (obj) {
        json_object_get(id);
        json_object_object_add(obj, "id", id);
        json_add_int64(obj, "result", result);
    }
    return obj;
}

struct json_object *json_rpc_process_single(
	struct json_rpc *jrpc, struct json_object *json)
{
	struct json_method_ctx ctx = {0};
	ctx.id = json_object_object_get(json, "id");

	if (!json) {
		return json_rpc_gen_error(jrpc, ctx.id, JSON_RPC_PARSE_ERROR, "Parse error");
	}

	if (!is_jsonrpc(jrpc, json)) {
		return json_rpc_gen_error(jrpc, ctx.id, JSON_RPC_INVALID_REQUEST, "Invalid request");
	}

	struct json_object *result = json_object_object_get(json, "result");
	if (result == NULL)
		result = json_object_object_get(json, "response");
	struct json_object *error = json_object_object_get(json, "error");
	if (result || error) {
		struct json_request *r;
		int64_t id;
		if (json_get_int64(json, "id", &id) || !(r = json_rpc_find_request(jrpc, id))) {
			log_error("could not find callback for result ID %lu", (unsigned long)id);
			return NULL;
		}

		struct json_result_info result_info = {
			.flags = result ? 0 : JSON_RESULT_IS_ERROR,
			.id = id,
			.response = result ? result : error
		};

		r->cb(&result_info, r->arg);
		LL_DELETE(jrpc->requests, r);
		free(r);
		return NULL;
	}

	if (!json_get_str(json, "method", &ctx.method)) {
		struct json_object *params = json_object_object_get(json, "params");
		if (params && !(
			json_object_is_type(params, json_type_null)||
			json_object_is_type(params, json_type_object) ||
			json_object_is_type(params, json_type_array))) {
			return json_rpc_gen_error(jrpc, ctx.id, JSON_RPC_INVALID_REQUEST, "Invalid request");
		}

		struct json_method *m = find_method(jrpc, ctx.method);
		if (!m) {
			return ctx.id ? json_rpc_gen_error(jrpc, ctx.id, JSON_RPC_METHOD_NOT_FOUND,
				"Method not found") : NULL;
		}

		struct json_object *named_params = NULL;
		if (json_object_is_type(params, json_type_array) && m->params) {
			named_params = json_object_new_object();
			for (int i = 0; i < m->num_params; i++) {
				char *p = m->params[i];
				json_object_object_add(named_params, p, json_object_array_get_idx(params, i));
			}
			ctx.params = named_params;
		} else {
			ctx.params = params;
		}

		struct json_object *response = m->cb(&ctx, m->arg);
		if (named_params) {
			json_object_put(named_params);
		}
		return response;
	}

	log_info("Neither a request nor a response found in JSON message");
	puts(json_object_to_json_string_ext(json, 0));
	return NULL;
}

struct json_object * json_rpc_process(struct json_rpc *jrpc,
	struct json_object *json)
{
	if (json_object_is_type(json, json_type_array)) {
		int num_requests = json_object_array_length(json);
		if (num_requests == 0) {
			return json_rpc_gen_error(jrpc, NULL, JSON_RPC_INVALID_REQUEST, "Invalid request");
		}

		struct json_object *responses = json_object_new_array();
		for (int i = 0; i < num_requests; i++ ) {
			struct json_object *response =
				json_rpc_process_single(jrpc, json_object_array_get_idx(json, i));
			if (response) {
				json_object_array_add(responses, response);
			}
		}
		if (json_object_array_length(responses) == 0) {
			json_object_put(responses);
			responses = NULL;
		}
		return responses;
	} else {
		return json_rpc_process_single(jrpc, json);
	}
}
