/**
 * Copyright 2015 Rapid7
 * @brief Byte buffer queue
 * @file buffer_queue.h
 */

#ifndef _BUFFER_QUEUE_H_
#define _BUFFER_QUEUE_H_

#include <string.h>

struct buffer_queue;

struct buffer_queue * buffer_queue_new(void);

void buffer_queue_free(struct buffer_queue *q);

size_t buffer_queue_len(struct buffer_queue *q);

int buffer_queue_add(struct buffer_queue *q, const void *data, size_t len);

int buffer_queue_add_str(struct buffer_queue *q, char *str);

size_t buffer_queue_remove(struct buffer_queue *q, void *data, size_t len);

size_t buffer_queue_copy(struct buffer_queue *q, void *data, size_t len);

size_t buffer_queue_drain(struct buffer_queue *q, size_t len);

void buffer_queue_drain_all(struct buffer_queue *q);

void * buffer_queue_peek_msg(struct buffer_queue *q, size_t *len);

void * buffer_queue_remove_msg(struct buffer_queue *q, size_t *len);

ssize_t buffer_queue_remove_all(struct buffer_queue *q, void **data);

ssize_t buffer_queue_move_all(struct buffer_queue *dst, struct buffer_queue *src);

#endif
