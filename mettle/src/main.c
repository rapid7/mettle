#include "mettle.h"
#include "zlog.h"

int main()
{
	struct mettle *m = mettle_open();

	mettle_start(m);

	mettle_close(m);

	return 0;
}
