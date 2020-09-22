#pragma once

#include <arpa/inet.h>

class Connection {
  public:
    Connection(std::string username, struct sockaddr_in addr,
               socklen_t addr_len, int fd)
        : username(username), addr(addr), addr_len(addr_len), fd(fd) {}

    bool operator==(const Connection &c) const { return this->fd == c.fd; }

    std::string username;
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len;
};

class ConnectionHash {
  public:
    size_t operator()(const Connection &c) const { return c.fd; }
};
