#pragma once

#include "whisp-server/user.h"

#include <arpa/inet.h>
#include <iostream>
#include <string>

class Connection {
public:
  Connection(User user, struct sockaddr_in addr, socklen_t addr_len,
             int fd)
      : user(user), addr(addr), addr_len(addr_len), fd(fd) {}

  void set_user(User new_user);

  bool operator==(const Connection &c) const { return this->fd == c.fd; }
  friend std::ostream &operator<<(std::ostream &os, const Connection &c) {
    os << "<" << c.user.username << " " << inet_ntoa(c.addr.sin_addr) << ":"
       << c.addr.sin_port << ">";
    return os;
  }

  User user;
  struct sockaddr_in addr;
  socklen_t addr_len;
  int fd;
};

class ConnectionHash {
public:
  size_t operator()(const Connection *const &c) const { return c->fd; }
};
