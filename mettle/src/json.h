/**
 * @brief json utilities
 * @file json.h
 */

#ifndef _JSON_H_
#define _JSON_H_

#include <stdbool.h>

#include <json-c/json.h>
#include "bufferev.h"

struct json_object *json_read_file(const char *json_file);

struct json_object * json_read_buf(const void *buf, ssize_t buf_len);

struct json_object *json_read_bufferev(struct bufferev *bev, struct json_tokener *tok);

int json_add_str(struct json_object *json, const char *key, const char *val);

int json_add_str_fmt(struct json_object *json, const char *key, const char *format, ...)
	__attribute__((format(printf, 3, 4)));

int json_add_int32(struct json_object *json, const char *key, int32_t val);

int json_add_int64(struct json_object *json, const char *key, int64_t val);

int json_add_double(struct json_object *json, const char *key, double val);

int json_add_bool(struct json_object *json, const char *key, bool val);

int json_get_str(json_object *json, const char *key, const char **dst);

int json_get_int32(json_object *json, const char *key, int32_t *dst);

int json_get_int64(json_object *json, const char *key, int64_t *dst);

int json_get_double(json_object *json, const char *key, double *dst);

int json_get_bool(json_object *json, const char *key, bool *dst);

#endif
