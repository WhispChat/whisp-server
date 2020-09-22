#pragma once

#include <string.h>
#include <string>
#include <strings.h>
#include <unistd.h>
#include <vector>

#include "whisp-server/connection.h"
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
    virtual void handle_connection(Connection conn);

    const std::string &host;
    int port;
    std::size_t max_conn;

    int serv_fd;
    struct sockaddr_in serv_addr;
    std::vector<Connection> connections;
};
