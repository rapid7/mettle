#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <wordexp.h>

#include "log.h"
#include "process.h"
#include "buffer_queue.h"
#include "uthash.h"

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
	struct passwd pwd, *result;
	int bufsize = 8192;
	void *buf = NULL;
	int rc;
	do {
		buf = realloc(buf, bufsize);
		if (buf == NULL) {
			return -1;
		}
		rc = getpwnam_r(user, &pwd, buf, bufsize, &result);
		bufsize += 8192;
	} while (rc == ERANGE && bufsize < 1048576);

	if (rc == 0) {
		if (setuid(pwd.pw_uid))
			exit(1);

		if (setgid(pwd.pw_gid))
			exit(1);
	}

	free(buf);
	return rc;
}

static void exec_child(struct procmgr *mgr,
    const char *file, struct process_options *opts)
{
	int argc = 1;
	char **argv = malloc(2 * sizeof(char *));

	if (opts) {
		if (opts->cwd != NULL && chdir(opts->cwd)) {
			exit(1);
		}
		if (opts->user != NULL) {
			switch_user(opts->user);
		}
		if (opts->env != NULL) {
			environ = opts->env;
		}
		if (opts->process_name) {
			argv[0] = strdup(opts->process_name);
		}
	}

	if (argv[0] == NULL) {
		argv[0] = strdup(file);
	}

	if (opts && opts->args) {
		wordexp_t we = {0};
		if (wordexp(opts->args, &we, 0) == 0) {
			for (int i = 0; i < we.we_wordc; i++) {
				log_info("%s %d", we.we_wordv[i], i);
				argv = realloc(argv, (argc + 2) * sizeof(char *));
				if (!argv) {
					exit(1);
				}
				argv[argc + 1] = strdup(we.we_wordv[i]);
				if (!argv[argc + 1]) {
					exit(1);
				}
				argc++;
			}
			wordfree(&we);
		}
	}

	argv[argc] = NULL;

	ev_loop_fork(EV_DEFAULT);

	execvp(file, argv);
	exit(1);
}

static void child_cb(struct ev_loop *loop, struct ev_child *w, int revents)
{
	struct process *process = w->data;
	struct procmgr *mgr = process->mgr;

	log_debug("child pid %u exited status %u", w->pid, w->rstatus);
	HASH_DEL(process->mgr->processes, process);

	ev_child_stop(loop, w);
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
		process->out_cb(process->out.queue, process->cb_arg);
	}
}

static void stderr_cb(struct ev_loop *loop, struct ev_io *w, int events)
{
	struct process *process = w->data;

	if (read_fd_into_queue(w->fd, process->err.queue) > 0) {
		process->err_cb(process->err.queue, process->cb_arg);
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

struct process * process_create(struct procmgr *mgr,
    const char *file, struct process_options *opts)
{
	int stdin_pair[2];
	if (pipe(stdin_pair) == -1) {
		return NULL;
	}

	int stdout_pair[2];
	if (pipe(stdout_pair) == -1) {
		return NULL;
	}

	int stderr_pair[2];
	if (pipe(stderr_pair) == -1) {
		return NULL;
	}

	struct process *p = calloc(1, sizeof(*p));
	if (p == NULL) {
		return NULL;
	}

	pid_t pid = fork();
	if (pid == 0) {
		dup2(stdin_pair[0], STDIN_FILENO);
		dup2(stdout_pair[1], STDOUT_FILENO);
		dup2(stderr_pair[1], STDERR_FILENO);

		close(stdin_pair[1]);
		close(stdin_pair[0]);
		close(stdout_pair[1]);
		close(stdout_pair[0]);
		close(stderr_pair[1]);
		close(stderr_pair[0]);

		exec_child(mgr, file, opts);
		return NULL;

	} else if (pid == -1) {
		close(stdin_pair[1]);
		close(stdin_pair[0]);
		close(stdout_pair[1]);
		close(stdout_pair[0]);
		close(stderr_pair[1]);
		close(stderr_pair[0]);
		free(p);
		return NULL;
	}
	p->pid = pid;

	/*
	 * Add to the hash before starting the signal watcher
	 */
	p->mgr = mgr;
	HASH_ADD_INT(mgr->processes, pid, p);

	log_debug("child pid %u started", p->pid);

	/*
	 * Register exit handler
	 */
	p->cw.data = p;
	ev_child_init(&p->cw, child_cb, p->pid, 0);
	ev_child_start(mgr->loop, &p->cw);

	/*
	 * Setup stdin
	 */
	close(stdin_pair[0]);
	fcntl(stdin_pair[1], F_SETFL, O_NONBLOCK);
	p->in_fd = stdin_pair[1];

	/*
	 * Register stdout watcher
	 */
	p->out_fd = stdout_pair[1];
	fcntl(stdout_pair[0], F_SETFL, O_NONBLOCK);
	p->out.queue = buffer_queue_new();
	p->out.w.data = p;
	ev_io_init(&p->out.w, stdout_cb, stdout_pair[0], EV_READ);
	ev_io_start(mgr->loop, &p->out.w);

	/*
	 * Register stderr watcher
	 */
	p->err_fd = stderr_pair[1];
	fcntl(stderr_pair[0], F_SETFL, O_NONBLOCK);
	p->err.queue = buffer_queue_new();
	p->err.w.data = p;
	ev_io_init(&p->err.w, stderr_cb, stderr_pair[0], EV_READ);
	ev_io_start(mgr->loop, &p->err.w);

	return p;
}

int process_kill(struct process* process)
{
	if (process && process->pid) {
		return kill(process->pid, SIGINT);
	}
	return -1;
}

ssize_t process_read(struct process *process, void *buf, size_t buf_len)
{
	size_t bytes_read = buffer_queue_remove(process->out.queue, buf, buf_len);
	if (bytes_read < buf_len) {
		bytes_read += buffer_queue_remove(process->err.queue,
				buf + bytes_read, buf_len - bytes_read);
	}
	return bytes_read;
}

ssize_t process_write(struct process *process, const void *buf, size_t buf_len)
{
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

void procmgr_free(struct procmgr *mgr)
{
	if (mgr->processes) {
		struct process *process, *tmp;
		HASH_ITER(hh, mgr->processes, process, tmp) {
			process_kill(process);
			HASH_DEL(mgr->processes, process);
			ev_child_stop(mgr->loop, &process->cw);
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
