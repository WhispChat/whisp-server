#pragma once

#include "whisp-protobuf/cpp/client.pb.h"
#include "whisp-protobuf/cpp/server.pb.h"
#include "whisp-server/connection.h"
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
  void send_message(const google::protobuf::Message &msg, Connection conn);
  void broadcast(const google::protobuf::Message &msg);
  bool parse_command(Connection *conn, client::Command cmd);
  void close_connection(Connection *conn);
  std::string get_users_list();
  server::Status get_server_status();
  server::Message create_message(server::Message::MessageType type,
                                 std::string content);

  const std::string &host;
  int port;
  std::size_t max_conn;

  int serv_fd;
  struct sockaddr_in serv_addr;

  std::unordered_set<Connection *, ConnectionHash> connections;
};
