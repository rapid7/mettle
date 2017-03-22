
#include "tlv.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <linux/videodev2.h>

#define CLEAR(x) memset (&(x), 0, sizeof (x))

#define TLV_TYPE_WEBCAM_IMAGE          (TLV_META_TYPE_RAW     | (TLV_EXTENSIONS + 1))
#define TLV_TYPE_WEBCAM_INTERFACE_ID   (TLV_META_TYPE_UINT    | (TLV_EXTENSIONS + 2))
#define TLV_TYPE_WEBCAM_QUALITY        (TLV_META_TYPE_UINT    | (TLV_EXTENSIONS + 3))
#define TLV_TYPE_WEBCAM_NAME           (TLV_META_TYPE_STRING  | (TLV_EXTENSIONS + 4))

struct buffer
{
  void *start;
  size_t length;
};
struct buffer *buffers = NULL;
unsigned int n_buffers = 0;
int fd;

static int xioctl(int fd, int request, void *arg)
{
  int r;
  do {
    r = ioctl(fd, request, arg);
  } while (-1 == r && EINTR == errno);
  return r;
}

struct tlv_packet *webcam_get_frame(struct tlv_handler_ctx *ctx)
{
  fd_set fds;
  struct timeval tv;
  int r;
  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  /* Timeout. */
  tv.tv_sec = 1;
  tv.tv_usec = 0;

  r = select(fd + 1, &fds, NULL, NULL, &tv);
  if (r == -1) {
    return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
  }

  struct v4l2_buffer buf;
  CLEAR(buf);
  buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  buf.memory = V4L2_MEMORY_MMAP;
  if (xioctl(fd, VIDIOC_DQBUF, &buf) == -1 ||
      buf.index >= n_buffers) {
    return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
  }

  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  p = tlv_packet_add_raw(p, TLV_TYPE_WEBCAM_IMAGE, buffers[buf.index].start, buf.length);

  if (xioctl(fd, VIDIOC_QBUF, &buf) == -1) {
    return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
  }
  return p;
}

int camera_open(int id)
{
  struct stat st;
  char dev_name[64];
  snprintf(dev_name, sizeof(dev_name), "/dev/video%d", id);

  if (stat(dev_name, &st) == -1) {
    return -1;
  }

  if (!S_ISCHR(st.st_mode)) {
    return -1;
  }

  fd = open(dev_name, O_RDWR | O_NONBLOCK, 0);
  if (fd == -1) {
    return -1;
  }
  return fd;
}

int camera_start()
{
  struct v4l2_format fmt;
  CLEAR(fmt);
  fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
  fmt.fmt.pix.field = V4L2_FIELD_INTERLACED;

  if (xioctl(fd, VIDIOC_S_FMT, &fmt) == -1) {
    return -1;
  }
  
  struct v4l2_requestbuffers req;
  CLEAR(req);
  req.count = 4;
  req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  req.memory = V4L2_MEMORY_MMAP;

  if (xioctl(fd, VIDIOC_REQBUFS, &req) == -1) {
    return -1;
  }

  if (req.count < 1) {
    return -1;
  }

  buffers = calloc(req.count, sizeof(*buffers));

  if (!buffers) {
    return -1;
  }

  for (n_buffers = 0; n_buffers < req.count; ++n_buffers) {
    struct v4l2_buffer buf;

    CLEAR(buf);

    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = n_buffers;

    if (xioctl(fd, VIDIOC_QUERYBUF, &buf) == -1) {
      return -1;
    }

    buffers[n_buffers].length = buf.length;
    buffers[n_buffers].start = mmap(NULL,
        buf.length,
        PROT_READ | PROT_WRITE,
        MAP_SHARED /* recommended */,
        fd, buf.m.offset);

    if (buffers[n_buffers].start == MAP_FAILED) {
      return -1;
    }
  }

  unsigned int i;
  for (i = 0; i < n_buffers; ++i)
  {
    struct v4l2_buffer buf;
    CLEAR(buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = i;

    if (xioctl(fd, VIDIOC_QBUF, &buf) == -1) {
      return -1;
    }
  }

  enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if (xioctl(fd, VIDIOC_STREAMON, &type) == -1) {
    return -1;
  }

  return 0;
}

struct tlv_packet *webcam_start(struct tlv_handler_ctx *ctx)
{
  uint32_t deviceIndex = 0;
  uint32_t quality = 0;
  tlv_packet_get_u32(ctx->req, TLV_TYPE_WEBCAM_INTERFACE_ID, &deviceIndex);
  tlv_packet_get_u32(ctx->req, TLV_TYPE_WEBCAM_QUALITY, &quality);

  int result = camera_open(deviceIndex - 1);
  if (result == -1) {
    return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
  }

  result = camera_start();
  if (result == -1) {
    return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
  }

  return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

struct tlv_packet *webcam_stop(struct tlv_handler_ctx *ctx)
{
  enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if (xioctl(fd, VIDIOC_STREAMOFF, &type) == -1) {
    return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
  }

  unsigned int i;
  for (i = 0; i < n_buffers; ++i) {
    if (munmap(buffers[i].start, buffers[i].length) == -1) {
      return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }
  }
  free(buffers);

  close(fd);

  return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

struct tlv_packet *webcam_list(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

  for (int i=0;i<10;i++) {
    int fd = camera_open(i);
    if (fd == -1) {
      continue;
    }

    struct v4l2_capability cap;
    int result = xioctl(fd, VIDIOC_QUERYCAP, &cap);

    if (result == -1) {
      if (errno == EINVAL) {
        break;
      } else {
        continue;
      }
    }

    if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
      continue;
    }

    if (!(cap.capabilities & V4L2_CAP_STREAMING)) {
      continue;
    }

    p = tlv_packet_add_str(p, TLV_TYPE_WEBCAM_NAME, (const char*)cap.card);
  }
  return p;
}
