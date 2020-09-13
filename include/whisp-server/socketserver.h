#pragma once

#include <iostream>
#include <string.h>
#include <string>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <thread>

class TCPSocketServer {
  public:
    TCPSocketServer(const std::string &host, int port, std::size_t max_conn)
        : host(host), port(port), max_conn(max_conn) {}
    void initialize();
    void serve();

    ~TCPSocketServer();

  private:
    virtual void handle_connection(int client_sock_fd);

    const std::string &host;
    int port;
    std::size_t max_conn;

    int sock_fd;
    struct sockaddr_in serv_addr;
};
