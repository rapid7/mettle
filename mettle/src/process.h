#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <ev.h>
#include "buffer_queue.h"

struct process;
struct progmgr;

struct procmgr * procmgr_new(struct ev_loop *loop);

void procmgr_free(struct procmgr *mgr);

typedef void (*process_exit_cb_t)(struct process *, int exit_status, void *arg);

typedef	void (*process_read_cb_t)(struct buffer_queue *queue, void *arg);

struct process_options {
	const char *process_name;       /* Alternate process name */
	const char *cwd;                /* Current working directory */
	const char *user;               /* User to start the process as */

	process_read_cb_t stdout_cb;    /* Stdout callback */
	process_read_cb_t stderr_cb;    /* Stderr callback */
	process_exit_cb_t exit_cb;      /* Process exit callback. */

	void *cb_arg;                   /* Callback argument */
};

/*
 * Create a new process
 */
struct process * process_create(struct procmgr *mgr,
    const char *file, char *const *args, char **env,
    struct process_options *opts);

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
 * Returns the PID of the given process
 */
pid_t process_get_pid(struct process *p);

#endif
