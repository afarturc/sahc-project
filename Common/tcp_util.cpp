#include "tcp_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int tcp_listen(const char* host, int port, int backlog)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "tcp_listen: invalid host %s\n", host);
        close(fd);
        return -1;
    }

    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

int tcp_accept(int listen_fd)
{
    sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    int fd = accept(listen_fd, (sockaddr*)&peer, &plen);
    if (fd < 0) {
        if (errno != EINTR) perror("accept");
        return -1;
    }
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    return fd;
}

int tcp_connect(const char* host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "tcp_connect: invalid host %s\n", host);
        close(fd);
        return -1;
    }

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    return fd;
}

int tcp_send_all(int fd, const void* buf, size_t len)
{
    const uint8_t* p = (const uint8_t*)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            return -1;
        }
        if (n == 0) return -1;
        p    += (size_t)n;
        left -= (size_t)n;
    }
    return 0;
}

int tcp_recv_all(int fd, void* buf, size_t len)
{
    uint8_t* p = (uint8_t*)buf;
    size_t left = len;
    size_t got  = 0;
    while (left > 0) {
        ssize_t n = recv(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            return -1;
        }
        if (n == 0) return got == 0 ? 1 : -1;
        p    += (size_t)n;
        left -= (size_t)n;
        got  += (size_t)n;
    }
    return 0;
}
