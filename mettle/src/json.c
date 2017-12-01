#include "log.h"
#include "json.h"

#include <errno.h>

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
		buf_len = fread(buf, 1, sizeof buf, file);
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
		buf_len = bufferev_read(bev, buf, sizeof buf);
		if (buf_len) {
			obj = json_tokener_parse_ex(tok, buf, buf_len);
			rc = json_tokener_get_error(tok);
		}
	} while (buf_len && rc == json_tokener_continue);

	return obj;
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
		if (errno != EINVAL) {
            return 0;
        }
    }
    return -1;
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
