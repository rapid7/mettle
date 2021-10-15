#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/types.h>

#include "argv_split.h"
#include "log.h"
#include "process.h"
#include "buffer_queue.h"
#include "uthash.h"
#include "utils.h"

struct process_queue {
	struct ev_io w;
	struct buffer_queue *queue;
};

struct process {
	struct procmgr *mgr;

	struct process_queue out, err;
	process_read_cb_t out_cb, err_cb;
	int in_fd;
	int out_fd;
	int err_fd;

	struct ev_child cw;
	process_exit_cb_t exit_cb;

	void *cb_arg;

	UT_hash_handle hh;
	pid_t pid;
};

struct procmgr {
	struct ev_loop *loop;
	struct process *processes;
};

extern char **environ;

pid_t process_get_pid(struct process *process)
{
	return process->pid;
}

static void free_process_queue(struct ev_loop *loop, struct process_queue *pipe)
{
	if (pipe->w.fd >= 0) {
		close(pipe->w.fd);
		ev_io_stop(loop, &pipe->w);
	}

	if (pipe->queue) {
		buffer_queue_free(pipe->queue);
		pipe->queue = NULL;
	}
}

static void free_process(struct process *process)
{
	close(process->in_fd);
	close(process->out_fd);
	close(process->err_fd);
	free_process_queue(process->mgr->loop, &process->out);
	free_process_queue(process->mgr->loop, &process->err);
	free(process);
}

static int switch_user(const char *user)
{
	return 0;
}

static char *shell_path(void)
{
	char * shells[] = { "/bin/sh", "/system/bin/sh", "/bin/bash", "/usr/local/bin/bash" };
	for (int i = 0; i < COUNT_OF(shells); i++) {
		if (access(shells[i], X_OK) == 0) {
			return shells[i];
		}
	}
	return NULL;
}

static void child_cb(struct ev_loop *loop, struct ev_child *w, int revents)
{
	struct process *process = w->data;
	struct procmgr *mgr = process->mgr;

	//log_debug("child pid %u exited status %u", w->pid, w->rstatus);
	HASH_DEL(process->mgr->processes, process);

	//ev_child_stop(loop, w);
	if (process->exit_cb) {
		process->exit_cb(process, w->rstatus, process->cb_arg);
	}

	free_process(process);
}

static size_t read_fd_into_queue(int fd, struct buffer_queue *queue)
{
	char buf[8192];
	ssize_t n;
	size_t len = 0;

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		buffer_queue_add(queue, buf, n);
		len += n;
	}

	return len;
}

static void stdout_cb(struct ev_loop *loop, struct ev_io *w, int events)
{
	struct process *process = w->data;

	if (read_fd_into_queue(w->fd, process->out.queue) > 0) {
		if (process->out_cb) {
			process->out_cb(process, process->out.queue, process->cb_arg);
		}
	}
}

static void stderr_cb(struct ev_loop *loop, struct ev_io *w, int events)
{
	struct process *process = w->data;

	if (read_fd_into_queue(w->fd, process->err.queue) > 0) {
		if (process->err_cb) {
			process->err_cb(process, process->err.queue, process->cb_arg);
		}
	}
}

void process_set_callbacks(struct process *p,
	process_read_cb_t stdout_cb,
	process_read_cb_t stderr_cb,
	process_exit_cb_t exit_cb,
	void *cb_arg)
{
	p->out_cb = stdout_cb;
	p->err_cb = stderr_cb;
	p->exit_cb = exit_cb;
	p->cb_arg = cb_arg;
}

void procmgr_setup_env(void)
{
}

struct process * process_create(struct procmgr *mgr,
	const char *file,
	const unsigned char *bin_image, size_t bin_image_len,
	struct process_options *opts)
{
	struct process *p = calloc(1, sizeof(*p));
	if (p == NULL) {
		return NULL;
	}

	/*
	pid_t pid = fork();
	p->pid = pid;
	*/

	/*
	 * Add to the hash before starting the signal watcher
	 */
	p->mgr = mgr;
	HASH_ADD_INT(mgr->processes, pid, p);

	//log_debug("child pid %u started", p->pid);

	/*
	 * Register exit handler
	 */
	p->cw.data = p;
	ev_child_init(&p->cw, child_cb, p->pid, 0);
	//ev_child_start(mgr->loop, &p->cw);

	/*
	 * Setup stdin
	 */
	/*
	close(stdin_pair[0]);
	fcntl(stdin_pair[1], F_SETFL, O_NONBLOCK);
	p->in_fd = stdin_pair[1];
	*/

	/*
	 * Register stdout watcher
	 */
	/*
	p->out_fd = stdout_pair[1];
	fcntl(stdout_pair[0], F_SETFL, O_NONBLOCK);
	p->out.queue = buffer_queue_new();
	p->out.w.data = p;
	ev_io_init(&p->out.w, stdout_cb, stdout_pair[0], EV_READ);
	ev_io_start(mgr->loop, &p->out.w);
	*/

	/*
	 * Register stderr watcher
	 */
	/*
	p->err_fd = stderr_pair[1];
	fcntl(stderr_pair[0], F_SETFL, O_NONBLOCK);
	p->err.queue = buffer_queue_new();
	p->err.w.data = p;
	ev_io_init(&p->err.w, stderr_cb, stderr_pair[0], EV_READ);
	ev_io_start(mgr->loop, &p->err.w);
	*/

	return p;
}

struct process * process_create_from_executable(struct procmgr *mgr,
	const char *file, struct process_options *opts)
{
	return process_create(mgr, file, NULL, 0, opts);
}

struct process * process_create_from_executable_buf(struct procmgr *mgr,
	const unsigned char *exe, struct process_options *opts)
{
	/* TODO: reflective loading not implemented for PEs */
	return NULL;
}

struct process * process_create_from_binary_image(struct procmgr *mgr,
	const unsigned char *bin_image, size_t bin_image_len,
	struct process_options *opts)
{
	return process_create(mgr, NULL, bin_image, bin_image_len, opts);
}


int process_kill(struct process* process)
{
	if (process && process->pid) {
		//return kill(process->pid, SIGINT);
	}
	return -1;
}

struct process * process_by_pid(struct procmgr *mgr, pid_t pid)
{
	struct process *p;
	HASH_FIND_INT(mgr->processes, &pid, p);
	return p;
}

int process_kill_by_pid(struct procmgr *mgr, pid_t pid)
{
	struct process *p = process_by_pid(mgr, pid);
	return process_kill(p);
}

ssize_t process_read(struct process *process, void *buf, size_t buf_len)
{
	if (process == NULL) {
		return -1;
	}

	size_t bytes_read = buffer_queue_remove(process->out.queue, buf, buf_len);
	if (bytes_read < buf_len) {
		bytes_read += buffer_queue_remove(process->err.queue,
				buf + bytes_read, buf_len - bytes_read);
	}
	return bytes_read;
}

ssize_t process_write(struct process *process, const void *buf, size_t buf_len)
{
	if (process == NULL) {
		return -1;
	}

	ssize_t len;
	for (len = 0; len < buf_len;) {
		ssize_t n;
		do {
			n = write(process->in_fd, buf + len, buf_len - len);
		} while (n == -1 && errno == EINTR);

		if (n < 0) {
			break;
		}
		len += n;
	}
	return len > 0 ? len : -1;
}

void procmgr_iter_processes(struct procmgr *mgr,
		void (*cb)(struct process *, void *process_arg, void *arg), void *arg)
{
	struct process *process, *tmp;
	HASH_ITER(hh, mgr->processes, process, tmp) {
		cb(process, process->cb_arg, arg);
	}
}

void procmgr_free(struct procmgr *mgr)
{
	if (mgr->processes) {
		struct process *process, *tmp;
		HASH_ITER(hh, mgr->processes, process, tmp) {
			process_kill(process);
			HASH_DEL(mgr->processes, process);
			//ev_child_stop(mgr->loop, &process->cw);
			free_process(process);
		}
	}
	free(mgr);
}

struct procmgr *procmgr_new(struct ev_loop *loop)
{
	struct procmgr *mgr = calloc(1, sizeof(*mgr));
	if (mgr) {
		mgr->loop = loop;
	}
	return mgr;
}
