#pragma once

#include "whisp-server/connection.h"
#include <string>
#include <unordered_set>

class TCPSocketServer {
  public:
    TCPSocketServer(const std::string &host, int port, std::size_t max_conn)
        : host(host), port(port), max_conn(max_conn) {}
    void initialize();
    void serve();

    ~TCPSocketServer();

  private:
    virtual void handle_connection(Connection conn);
    void close_connection(Connection conn);

    const std::string &host;
    int port;
    std::size_t max_conn;

    int serv_fd;
    struct sockaddr_in serv_addr;

    std::unordered_set<Connection, ConnectionHash> connections;
};
