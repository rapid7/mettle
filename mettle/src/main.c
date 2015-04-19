#include <signal.h>
#include <stdio.h>

#include <util/log.h>
#include "mettle.h"

int main()
{
	/*
	 * Disable SIGPIPE process aborts.
	 */
	sigignore(SIGPIPE);

	/*
	 * Start system logger
	 */
    log_init_file(stderr);
    log_init_flush_thread();

	/*
	 * Allocate the main dispatcher
	 */
	struct mettle *m = mettle();
	if (m == NULL) {
		log_error("could not initialize");
		return 1;
	}

	/*
	 * Start mettle and event loop
	 */
	mettle_start(m);

	mettle_free(m);

	return 0;
}
