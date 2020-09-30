#pragma once

#include "whisp-server/connection.h"
#include "whisp-server/message.h"
#include <string>
#include <unordered_set>

class TCPSocketServer {
  public:
    TCPSocketServer(const std::string &host, int port, std::size_t max_conn)
        : host(host), port(port), max_conn(max_conn) {}
    void initialize();
    void serve();
    void cleanup();

  private:
    virtual void handle_connection(Connection *conn);
    void send_message(std::string msg, Connection conn);
    void broadcast(std::string msg);
    bool parse_command(Connection *conn, Command cmd);
    void close_connection(Connection *conn);

    const std::string &host;
    int port;
    std::size_t max_conn;

    int serv_fd;
    struct sockaddr_in serv_addr;

    std::unordered_set<Connection *, ConnectionHash> connections;
};
