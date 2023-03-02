#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <stdlib.h>
#endif
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "utils.h"

int
make_socket_nonblocking(int fd)
{
#ifdef _WIN32
	unsigned long nonblocking = 1;
	if (ioctlsocket(fd, FIONBIO, &nonblocking) == SOCKET_ERROR) {
		return -1;
	}
#else
	int flags;
	if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
		return -1;
	}
	if (!(flags & O_NONBLOCK)) {
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			return -1;
		}
	}
#endif
	return 0;
}

char *
parse_sockaddr(struct sockaddr_storage *addr, uint16_t *port)
{
	char host[INET6_ADDRSTRLEN] = { 0 };

	if (addr->ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)addr;
		*port = ntohs(s->sin_port);
		inet_ntop(AF_INET, &s->sin_addr, host, INET6_ADDRSTRLEN);
	} else if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;
		*port = ntohs(s->sin6_port);
		inet_ntop(AF_INET6, &s->sin6_addr, host, INET6_ADDRSTRLEN);

		if (IN6_IS_ADDR_V4MAPPED(&s->sin6_addr)) {
			struct sockaddr_in addr4;

			memset(&addr4, 0, sizeof(addr4));
			memcpy(&addr4.sin_addr.s_addr, s->sin6_addr.s6_addr + 12, sizeof(addr4.sin_addr.s_addr));

			addr4.sin_family = AF_INET;
			addr4.sin_port   = s->sin6_port;

			inet_ntop(AF_INET, &addr4.sin_addr, host, INET6_ADDRSTRLEN);
		}
	}

	return strdup(host);
}
