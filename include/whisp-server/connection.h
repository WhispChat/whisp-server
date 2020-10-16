#pragma once

#include <arpa/inet.h>
#include <iostream>
#include <string>

class Connection {
public:
  Connection(std::string username, struct sockaddr_in addr, socklen_t addr_len,
             int fd)
      : username(username), addr(addr), addr_len(addr_len), fd(fd) {}

  void set_username(std::string username);

  bool operator==(const Connection &c) const { return this->fd == c.fd; }
  friend std::ostream &operator<<(std::ostream &os, const Connection &c) {
    os << "<" << c.username << " " << inet_ntoa(c.addr.sin_addr) << ":"
       << c.addr.sin_port << ">";
    return os;
  }

  std::string username;
  int fd;
  struct sockaddr_in addr;
  socklen_t addr_len;
};

class ConnectionHash {
public:
  size_t operator()(const Connection *const &c) const { return c->fd; }
};
