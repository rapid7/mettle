#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <ev.h>
#include "buffer_queue.h"

#if HAVE_REFLECT
#include <reflect.h>
#else
#define reflect_execv(...) ((void *) -1)
#endif

struct process;
struct progmgr;

struct procmgr * procmgr_new(struct ev_loop *loop);

void procmgr_setup_env(void);

void procmgr_free(struct procmgr *mgr);

typedef void (*process_exit_cb_t)(struct process *, int exit_status, void *arg);

typedef	void (*process_read_cb_t)(struct process *, struct buffer_queue *queue, void *arg);

struct process_options {
	const char *args;               /* Process arguments (none if not specified) */
	char **env;                     /* Process environment (inherited if not specified) */
	const char *process_name;       /* Alternate process name */
	const char *cwd;                /* Current working directory */
	const char *user;               /* User to start the process as */
#define PROCESS_CREATE_SUBSHELL		(0x00000001 << 0)
#define PROCESS_CREATE_REFLECT		(0x00000001 << 1)
	int flags;
};

/*
 * Create a new process
 */
struct process * process_create_from_executable(struct procmgr *mgr,
	const char *file, struct process_options *opts);

struct process * process_create_from_executable_buf(struct procmgr *mgr,
	const unsigned char *elf, struct process_options *opts);

struct process * process_create_from_binary_image(struct procmgr *mgr,
	const unsigned char *bin_image, size_t bin_image_len,
	struct process_options *opts);

void process_set_callbacks(struct process *p,
	process_read_cb_t stdout_cb,
	process_read_cb_t stderr_cb,
	process_exit_cb_t exit_cb,
	void *cb_arg);

/*
 * Write to the process stdin
 */
ssize_t process_write(struct process *p, const void *buf, size_t nbyte);

/*
 * Reads from stdout/stderr
 */
ssize_t process_read(struct process *p, void *buf, size_t nbyte);

/*
 * Kill the given process. Cleanup happens asynchronously from this call.
 */
int process_kill(struct process* process);

/*
 * Enable nonblocking stdio on this process
 */
void process_set_nonblocking_stdio(void);

/*
 * Returns the managed process for a given PID
 */
struct process * process_by_pid(struct procmgr *mgr, pid_t pid);

/*
 * Kill the managed process for a given PID
 */
int process_kill_by_pid(struct procmgr *mgr, pid_t pid);

/*
 * Returns the PID of the given process
 */
pid_t process_get_pid(struct process *p);

/*
 * Returns the in_fd of the given process
 */
int process_get_in_fd(struct process *process);

/*
 * Iterate over all managed processes
 */
void procmgr_iter_processes(struct procmgr *mgr,
		void (*cb)(struct process *, void *process_arg, void *arg), void *arg);

#endif
