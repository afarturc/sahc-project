#ifndef _SAHC_TCP_UTIL_H_
#define _SAHC_TCP_UTIL_H_

#include <stddef.h>

// Bind and listen on host:port. Returns listening fd, or -1 on error.
int tcp_listen(const char* host, int port, int backlog);

// Accept one connection. Returns conn fd, or -1 on error.
int tcp_accept(int listen_fd);

// Connect to host:port. Returns conn fd, or -1 on error.
int tcp_connect(const char* host, int port);

// Send all bytes. Returns 0 on success, -1 on error (incl. peer close mid-send).
int tcp_send_all(int fd, const void* buf, size_t len);

// Receive exactly len bytes. Returns 0 on success, -1 on error, 1 on clean EOF
// before any bytes received.
int tcp_recv_all(int fd, void* buf, size_t len);

// Apply SO_RCVTIMEO / SO_SNDTIMEO. Either may be 0 to leave that direction
// blocking. Returns 0 on success, -1 on setsockopt failure.
int tcp_set_timeout(int fd, int recv_secs, int send_secs);

#endif
