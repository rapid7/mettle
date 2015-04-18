#include <signal.h>

#include "mettle.h"

int main()
{
	/*
	 * Disable SIGPIPE process aborts.
	 */
	sigignore(SIGPIPE);

	struct mettle *m = mettle_open();

	mettle_start(m);

	mettle_close(m);

	return 0;
}
