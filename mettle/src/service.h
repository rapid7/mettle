#ifndef _METTLE_SERVICE_H_
#define _METTLE_SERVICE_H_

enum persist_type {
	persist_none,
	persist_install,
	persist_uninstall
};

int start_service(const char *name, const char *path, const char *args,
	enum persist_type persist);

#endif
