#ifndef _EIO_RMTREE_H_
#define _EIO_RMTREE_H_

#include <eio.h>

eio_req *
eio_rmtree(const char *path, int pri, eio_cb cb, void *data);

#endif