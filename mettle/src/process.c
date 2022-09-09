#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pty.h>
#include <termios.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "argv_split.h"
#include "log.h"
#include "process.h"
#include "buffer_queue.h"
#include "uthash.h"
#include "utils.h"
#include "../util/util-common.h"
#include "tlv.h"

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

void procmgr_setup_env(void)
{
	const char *lang = getenv("LANG");
	if (lang == NULL) {
		setenv("LANG", "C", 0);
	}

	struct passwd *pwd = getpwuid(geteuid());
	if (pwd != NULL) {
		setenv("USER", pwd->pw_name, 0);
		setenv("HOME", pwd->pw_dir, 0);
	} else {
		setenv("USER", "nobody", 0);
		setenv("HOME", "/", 0);
	}

	const char *path = getenv("PATH");
	const char *def_path = \
			"/usr/local/sbin:"
			"/usr/local/bin:"
			"/usr/sbin:"
			"/usr/bin:"
			"/sbin:"
			"/bin:"
			"/usr/games:"
			"/usr/local/games:"
			"/system/bin:"
			"/system/sbin:"
			"/system/xbin";

	if (path != NULL) {
		char *new_path;
		if (asprintf(&new_path, "%s:%s", path, def_path)) {
			setenv("PATH", new_path, 1);
		}
	} else {
		setenv("PATH", def_path, 1);
	}
}

static void exec_child(struct procmgr *mgr,
	const char *file, struct process_options *opts)
{
	char *args = NULL, *proc = NULL;

	ev_loop_fork(EV_DEFAULT);
	ev_loop_destroy(EV_DEFAULT_UC);

	const char *process_name = file;
	if (opts) {
		if (opts->cwd != NULL && chdir(opts->cwd)) {
			abort();
		}
		if (opts->user != NULL) {
			switch_user(opts->user);
		}
		if (opts->env != NULL) {
			environ = opts->env;
		}
		if (opts->process_name) {
			process_name = opts->process_name;
		}
	}

	proc = strdup(process_name);


	if (opts && opts->args) {
		if (asprintf(&args, "%s %s", proc, opts->args) <= 0) {
			abort();
		}
	} else {
		args = proc;
	}

	char *sh = NULL;
	if (opts->flags & PROCESS_CREATE_SUBSHELL) {
		sh = shell_path();
	}

	if (sh) {
		execl(sh, sh, "-c", args, (char *)NULL);
	} else {
		size_t argc = 0;
		char **argv = NULL;
		argv = argv_split(args, argv, &argc);
		if (argv[0][0] == '/' && access(argv[0], X_OK)) {
			argv[0] = basename(argv[0]);
		}
		if (opts->flags & PROCESS_CREATE_REFLECT) {
			log_debug("%s: reflectively executing %p with %s", __FUNCTION__, file, args);
			reflect_execv((unsigned char *)file, argv);
		} else {
			execvp(file, argv);
		}
	}
	abort();
}

static void exec_image(struct procmgr *mgr,
	const unsigned char *image, size_t image_len,
	struct process_options *opts)
{
	char *args = NULL, *proc = NULL;

	ev_loop_fork(EV_DEFAULT);
	ev_loop_destroy(EV_DEFAULT_UC);

	// Variables we'll need to get the binary image running
	void (*e_entry)(long *, long *);
	long stack[9] = {0};
	long *dynv;

	// Locate the entry point address for the binary image (stored in the appended image info)
	struct bin_info *image_info = (struct bin_info*)(image + image_len - sizeof(*image_info));
	e_entry = (void *)(image + image_info->start_function);

	// ARGC, ARGV
	stack[0] = 1;
	stack[1] = (intptr_t)"libc.so";
	stack[2] = 0;

	// ENV
	stack[3] = (intptr_t)"LANG=C";
	stack[4] = 0;

	// AUXV
	stack[5] = AT_BASE; stack[6] = (intptr_t)image; // TODO: maybe let musl calculate?
	stack[7] = AT_NULL; stack[8] = 0;

	// Dynamic linker info:
	dynv = (void *)(image + image_info->dynamic_linker_info);

	log_debug("%s: jumping to %p loaded at %p\n", __FUNCTION__, e_entry, image);
	e_entry(stack, dynv);

	abort();
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
	if (len == 0) {
		log_debug("nothing on fd %d: %s", fd, strerror(errno));
	}

	return len;
}

static void child_cb(struct ev_loop *loop, struct ev_child *w, int revents)
{
	struct process *process = w->data;
	struct procmgr *mgr = process->mgr;

	log_debug("child pid %u exited status %u", w->pid, w->rstatus);
	HASH_DEL(process->mgr->processes, process);

	/*
	 * Read remaining data into the queue
	 */
	if (read_fd_into_queue(process->out_fd, process->out.queue) > 0) {
		if (process->out_cb) {
			process->out_cb(process, process->out.queue, process->cb_arg);
		}
	}

	if (read_fd_into_queue(process->err_fd, process->err.queue) > 0) {
		if (process->err_cb) {
			process->err_cb(process, process->err.queue, process->cb_arg);
		}
	}

	ev_child_stop(loop, w);

	if (process->exit_cb) {
		process->exit_cb(process, w->rstatus, process->cb_arg);
	}

	free_process(process);
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

static struct process * process_create(struct procmgr *mgr,
	const char *file,
	const unsigned char *bin_image, size_t bin_image_len,
	struct process_options *opts)
{

	int stdin_pair[2];
	int stdout_pair[2];

	int stderr_pair[2];
	if (pipe(stderr_pair) == -1) {
		return NULL;
	}

	struct process *p = calloc(1, sizeof(*p));
	if (p == NULL) {
		return NULL;
	}

	pid_t pid;
	if (opts->flags & PROCESS_EXECUTE_FLAG_PTY) {
		int master;

		pid = forkpty(&master, NULL, NULL, NULL);

		if (pid == 0) {
			struct termios tios;
			tcgetattr(master, &tios);
			tcsetattr(master, TCSADRAIN, &tios);
		}
		stdin_pair[0] = master;
		stdin_pair[1] = master;
		stdout_pair[0] = master;
		stdout_pair[1] = master;
	} else {
		if (pipe(stdin_pair) == -1) {
			return NULL;
		}

		if (pipe(stdout_pair) == -1) {
			return NULL;
		}

		pid = fork();
	}

	if (pid == 0) {
		dup2(stdin_pair[0], STDIN_FILENO);
		dup2(stdout_pair[1], STDOUT_FILENO);
		dup2(stderr_pair[1], STDERR_FILENO);

		close(stderr_pair[1]);
		close(stderr_pair[0]);

		if (opts->flags & PROCESS_CREATE_REFLECT) {
			exec_child(mgr, (char *)bin_image, opts);
		} else if (bin_image) {
			exec_image(mgr, bin_image, bin_image_len, opts);
		} else {
			exec_child(mgr, file, opts);
		}
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

	log_debug("child pid %lu started", (unsigned long)p->pid);

	/*
	 * Register exit handler
	 */
	p->cw.data = p;
	ev_child_init(&p->cw, child_cb, p->pid, 0);
	ev_child_start(mgr->loop, &p->cw);

	/*
	 * Setup stdin
	 */
	fcntl(stdin_pair[1], F_SETFL, O_NONBLOCK);
	p->in_fd = stdin_pair[1];

	/*
	 * Register stdout watcher
	 */
	p->out_fd = stdout_pair[0];
	fcntl(stdout_pair[0], F_SETFL, O_NONBLOCK);
	p->out.queue = buffer_queue_new();
	p->out.w.data = p;
	ev_io_init(&p->out.w, stdout_cb, stdout_pair[0], EV_READ);
	ev_io_start(mgr->loop, &p->out.w);

	/*
	 * Register stderr watcher
	 */
	p->err_fd = stderr_pair[0];
	fcntl(stderr_pair[0], F_SETFL, O_NONBLOCK);
	p->err.queue = buffer_queue_new();
	p->err.w.data = p;
	ev_io_init(&p->err.w, stderr_cb, stderr_pair[0], EV_READ);
	ev_io_start(mgr->loop, &p->err.w);

	log_debug("IO started on fds %d %d", p->out_fd, p->err_fd);

	close(stdin_pair[0]);
	close(stdout_pair[1]);
	close(stderr_pair[1]);

	return p;
}

struct process * process_create_from_executable(struct procmgr *mgr,
	const char *file, struct process_options *opts)
{
	return process_create(mgr, file, NULL, 0, opts);
}

/*
 * TODO:
 *  * Add process name imitation
 *  * Convert images to use this
 *  * Check for executable compatibility
 *  * Pass in size and bounds check operations
 */
struct process * process_create_from_executable_buf(struct procmgr *mgr,
	const unsigned char *buffer, struct process_options *opts)
{
#if HAVE_REFLECT
	return process_create(mgr, NULL, buffer, 0, opts);
#else
	return NULL;
#endif
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
		return kill(process->pid, SIGINT);
	}
	return -1;
}

void process_set_nonblocking_stdio(void)
{
	// Ensure stdin, stdout, and stderr are nonblocking.
	int flags;
	flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
	flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
	fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK);
	flags = fcntl(STDERR_FILENO, F_GETFL, 0);
	fcntl(STDERR_FILENO, F_SETFL, flags | O_NONBLOCK);
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

int process_get_in_fd(struct process *process) {
	return process->in_fd;
}
