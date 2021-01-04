#pragma once

#include "whisp-server/user.h"
#include "whisp-server/socketserver.h"

#include <arpa/inet.h>
#include <iostream>
#include <openssl/ssl.h>
#include <string>

class Connection {
public:
  Connection(User *user, struct sockaddr_in addr, socklen_t addr_len, int fd,
             SSL *ssl, TCPSocketServer socketserver);

  void set_user(User *new_user);
  void send_message(const google::protobuf::Message &msg);
  virtual void handle_connection(TCPSocketServer socketserver);

  bool operator==(const Connection &c) const { return this->fd == c.fd; }
  friend std::ostream &operator<<(std::ostream &os, const Connection &c) {
    os << "<" << c.user->username << " " << inet_ntoa(c.addr.sin_addr) << ":"
       << c.addr.sin_port << ">";
    return os;
  }

  User *user;
  SSL *ssl;
  struct sockaddr_in addr;
  socklen_t addr_len;
  int fd;
};

class ConnectionHash {
public:
  size_t operator()(const Connection *const &c) const { return c->fd; }
};
