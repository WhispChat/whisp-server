#pragma once

#include "whisp-protobuf/cpp/client.pb.h"
#include "whisp-protobuf/cpp/server.pb.h"
#include "whisp-server/command.h"
#include "whisp-server/connection.h"

#include <openssl/ssl.h>
#include <string>
#include <unordered_set>

class TCPSocketServer {
public:
  TCPSocketServer(const std::string &host, int port, std::size_t max_conn,
                  std::string cert_path, std::string key_path)
      : host(host), port(port), max_conn(max_conn), cert_path(cert_path),
        key_path(key_path) {}
  void initialize();
  void serve();
  void cleanup_one(Connection *conn);
  void cleanup_all();

  void broadcast(const google::protobuf::Message &msg);
  // TODO: This should be split to CommandManager later
  bool parse_command(Connection *conn, Command cmd);

private:
  void initialize_ssl_context();
  std::string get_supported_cipher_list();

  std::string get_users_list();

  server::Status get_server_status();
  server::Message create_message(server::Message::MessageType type,
                                 std::string content);

  bool parse_login_command(Connection *conn, std::vector<std::string> args);
  bool parse_register_command(Connection *conn, std::vector<std::string> args);
  bool parse_set_command(Connection *conn, std::vector<std::string> args);

  const std::string &host;
  int port;
  std::size_t max_conn;

  std::string cert_path;
  std::string key_path;
  SSL_CTX *ssl_ctx = nullptr;

  int serv_fd;
  struct sockaddr_in serv_addr;

  std::unordered_set<Connection *, ConnectionHash> connections;
};
