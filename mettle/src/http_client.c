#include <ctype.h>
#include <stdlib.h>

#include <curl/curl.h>
#include <eio.h>
#include <zlib.h>

#include "buffer_queue.h"
#include "http_client.h"
#include "log.h"

struct http_conn {
	CURL *easy_handle;
	CURLcode res;
	char *url;
	char error[CURL_ERROR_SIZE];
	void (*cb)(struct http_conn *, void *arg);
	void *cb_arg;

	void *content;
	size_t content_len;

	struct curl_slist *request_headers;
	struct curl_slist *response_headers;
	struct buffer_queue *response;
};

struct buffer_queue * http_conn_response_queue(struct http_conn *conn)
{
	return conn->response;
}

char *http_conn_response(struct http_conn *conn)
{
	void *data = NULL;
	ssize_t len = buffer_queue_remove_all(conn->response, &data);
	if (len > 0) {
		((char *)data)[len - 1] = '\0';
	}
	return data;
}

void *http_conn_response_raw(struct http_conn *conn, ssize_t *len)
{
	void *data = NULL;
	*len = buffer_queue_remove_all(conn->response, &data);
	return data;
}

int http_conn_response_code(struct http_conn *conn)
{
	long code = -1;
	curl_easy_getinfo(conn->easy_handle, CURLINFO_RESPONSE_CODE, &code);
	return code;
}

const char *http_conn_header_value(struct http_conn *conn, const char *key)
{
    if (conn->response_headers == NULL) {
        return NULL;
    }

    char *key_search = NULL;
    int rc = asprintf(&key_search, "%s: ", key);
    if (rc > 0 && key_search) {
        size_t key_len = strlen(key_search);
        struct curl_slist *header = conn->response_headers;
        do {
            if (!strncmp(key_search, header->data, key_len)) {
                free(key_search);
                return header->data + key_len;
            }
            header = header->next;
        } while (header);
    }
    free(key_search);
    return NULL;
}

void http_conn_free(struct http_conn *conn)
{
	if (conn) {
		log_info(" request free  %p", conn);
		free(conn->url);
		if (conn->response) {
			buffer_queue_free(conn->response);
		}
		if (conn->request_headers) {
			curl_slist_free_all(conn->request_headers);
		}
		if (conn->response_headers) {
			curl_slist_free_all(conn->response_headers);
		}
		if (conn->easy_handle) {
			curl_easy_cleanup(conn->easy_handle);
		}
		if (conn->content) {
			free(conn->content);
		}
		free(conn);
	}
}

static size_t write_cb(void *buf, size_t size, size_t nmemb, void *arg)
{
	size_t len = size * nmemb;
	struct http_conn *conn = arg;
	return (buffer_queue_add(conn->response, buf, len) == 0) ? len : 0;
}

static size_t header_cb(void *buf, size_t size, size_t nmemb, void *arg)
{
    struct http_conn *conn = arg;
    size_t len = size * nmemb;

	/*
	 * Ignore redirect headers
	 */
    if (http_conn_response_code(conn) == 302) {
        return len;
    }

    if (len > 2) {
        char *header = malloc(len + 1);
        if (header) {
            memcpy(header, buf, len);
            header[len] = '\0';
            for (size_t end = len - 1; end > 0 && isspace(header[end]); end--) {
                header[end] = '\0';
            }
            conn->response_headers = curl_slist_append(conn->response_headers, header);
            free(header);
        }
    }
    return len;
}

static int request_done(struct eio_req *req)
{
	struct http_conn *conn = req->data;
	if (conn->cb) {
		conn->cb(conn, conn->cb_arg);
	}
	http_conn_free(conn);
	return 0;
}

static void request(struct eio_req *req)
{
	struct http_conn *conn = req->data;
	conn->res = curl_easy_perform(conn->easy_handle);
}

static void *compress_content(const void *content, size_t content_len, size_t *compressed_len)
{
	int result;
	z_stream strm = { 0 };

	/*
	 * Avoid diminishing returns
	 */
	if (content_len < 256) {
		return NULL;
	}

	size_t comp_len = compressBound(content_len);
	void *buf = malloc(comp_len);

	if (buf == NULL) {
		return NULL;
	}

	result = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS | 16,
		MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);

	if (result != Z_OK) {
		switch (result) {
			case Z_MEM_ERROR:
			case Z_BUF_ERROR:
				break;
		}
		free(buf);
		buf = NULL;
		goto out;
	}

	strm.next_in = (Bytef *)content;
	strm.avail_in = content_len;
	strm.next_out = (Bytef *)buf;
	strm.avail_out = content_len;

	result = deflate(&strm, Z_FINISH);

	if (result != Z_STREAM_END) {
		free(buf);
		buf = NULL;
	} else {
		*compressed_len = strm.total_out;
	}

out:
	deflateEnd(&strm);
	return buf;
}

int http_request(const char *url, enum http_request req,
	void (*cb)(struct http_conn *, void *arg), void *cb_arg,
	struct http_request_data *data, struct http_request_opts *opts)
{
	struct http_conn *conn = calloc(1, sizeof *conn);
	log_info("request alloc %p", conn);
	if (conn == NULL) {
		return -1;
	}

	conn->url = strdup(url);
	if (conn->url == NULL) {
		goto err;
	}

	conn->response = buffer_queue_new();
	if (conn->response == NULL) {
		goto err;
	}

	conn->cb = cb;
	conn->cb_arg = cb_arg;

	conn->easy_handle = curl_easy_init();
	if (conn->easy_handle == NULL) {
		goto err;
	}

	curl_easy_setopt(conn->easy_handle, CURLOPT_URL, conn->url);
	curl_easy_setopt(conn->easy_handle, CURLOPT_HEADERFUNCTION, header_cb);
	curl_easy_setopt(conn->easy_handle, CURLOPT_HEADERDATA, conn);
	curl_easy_setopt(conn->easy_handle, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(conn->easy_handle, CURLOPT_WRITEDATA, conn);
	curl_easy_setopt(conn->easy_handle, CURLOPT_ERRORBUFFER, conn->error);
	curl_easy_setopt(conn->easy_handle, CURLOPT_PRIVATE, conn);
	curl_easy_setopt(conn->easy_handle, CURLOPT_FOLLOWLOCATION, 1L);

	/*
	 * Timeout after 60 seconds running < 1 byte/sec
	 */
	curl_easy_setopt(conn->easy_handle, CURLOPT_LOW_SPEED_TIME, 60L);
	curl_easy_setopt(conn->easy_handle, CURLOPT_LOW_SPEED_LIMIT, 1L);
	  

	/*

	* Wait for at most 30 seconds to establish a connection,

	* and 60 seconds for the transfer to complete.

	*

	* Just to prevent a hung connection from blocking the entire

	* http transport when sending the first HTTP request.

	*/

	curl_easy_setopt(conn->easy_handle, CURLOPT_CONNECTTIMEOUT, 30L);

	curl_easy_setopt(conn->easy_handle, CURLOPT_TIMEOUT, 60L);
	
	switch (req) {
		case http_request_get:
			break;
		case http_request_post:
			curl_easy_setopt(conn->easy_handle, CURLOPT_POST, 1L);
			break;
		case http_request_put:
			curl_easy_setopt(conn->easy_handle, CURLOPT_PUT, 1L);
			break;
		case http_request_delete:
			curl_easy_setopt(conn->easy_handle, CURLOPT_CUSTOMREQUEST, "DELETE");
			break;
	}

	if (data) {
		for (int i = 0; i < data->num_headers; i++) {
			conn->request_headers =
				curl_slist_append(conn->request_headers, data->headers[i]);
		}

		if (data->cookie_list) {
			curl_easy_setopt(conn->easy_handle, CURLOPT_COOKIEFILE, "");
			curl_easy_setopt(conn->easy_handle, CURLOPT_COOKIELIST, data->cookie_list);
		}

		if (data->referer) {
			curl_easy_setopt(conn->easy_handle, CURLOPT_REFERER, data->referer);
		}

		if (data->ua) {
			curl_easy_setopt(conn->easy_handle, CURLOPT_USERAGENT, data->ua);
		}

		if (data->content) {
			char *content_type = NULL;
			int rc = asprintf(&content_type, "Content-Type: %s",
					data->content_type ? data->content_type : "application/json");
			if (rc > 0) {
				conn->request_headers = curl_slist_append(conn->request_headers, content_type);
			}

			if (data->flags & HTTP_DATA_COMPRESS) {
				conn->content = compress_content(data->content,
						data->content_len, &conn->content_len);
				if (conn->content) {
					conn->request_headers = curl_slist_append(conn->request_headers,
								"Content-Encoding: gzip");
				}
			}

			if (conn->content == NULL) {
				conn->content = malloc(data->content_len);
				if (conn->content) {
					memcpy(conn->content, data->content, data->content_len);
					conn->content_len = data->content_len;
				}
			}

			if (conn->content) {
				curl_easy_setopt(conn->easy_handle, CURLOPT_POSTFIELDS, conn->content);
				curl_easy_setopt(conn->easy_handle, CURLOPT_POSTFIELDSIZE, (long)conn->content_len);
			}
		}
	}

	if (opts) {
		if (opts->ca_type == http_ca_type_path) {
			curl_easy_setopt(conn->easy_handle, CURLOPT_CAPATH, opts->ca);
		} else if (opts->ca_type == http_ca_type_bundle) {
			curl_easy_setopt(conn->easy_handle, CURLOPT_CAINFO, opts->ca);
		}

		if (opts->proxy.type != http_proxy_none) {
			curl_easy_setopt(conn->easy_handle, CURLOPT_PROXY, opts->proxy.hostname);
			curl_easy_setopt(conn->easy_handle, CURLOPT_PROXYPORT, opts->proxy.port);

			if (opts->proxy.auth_type != http_auth_none) {
				char *userpwd = NULL;
				int rc = asprintf(&userpwd, "%s:%s",
						opts->proxy.auth_user ? opts->proxy.auth_user : "",
						opts->proxy.auth_pass ? opts->proxy.auth_pass : "");
				if (rc > 0) {
					curl_easy_setopt(conn->easy_handle, CURLOPT_PROXYUSERPWD, userpwd);
					if (opts->proxy.auth_type == http_auth_basic) {
						curl_easy_setopt(conn->easy_handle, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
					} else if (opts->proxy.auth_type == http_auth_digest) {
						curl_easy_setopt(conn->easy_handle, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
					}
					free(userpwd);
				}
			}
		}

		if (opts->flags & HTTP_OPTS_VERBOSE) {
			curl_easy_setopt(conn->easy_handle, CURLOPT_VERBOSE, 1L);
		}
		if (opts->flags & HTTP_OPTS_SKIP_TLS_VALIDATION) {
			curl_easy_setopt(conn->easy_handle, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(conn->easy_handle, CURLOPT_SSL_VERIFYHOST, 0L);
		} else {
			curl_easy_setopt(conn->easy_handle, CURLOPT_SSL_VERIFYPEER, 1L);
			curl_easy_setopt(conn->easy_handle, CURLOPT_SSL_VERIFYHOST, 2L);
		}
	}

	if (conn->request_headers) {
		curl_easy_setopt(conn->easy_handle, CURLOPT_HTTPHEADER, conn->request_headers);
	}

	eio_custom(request, 0, request_done, conn);

	return 0;

err:
	http_conn_free(conn);
	return -1;
}
