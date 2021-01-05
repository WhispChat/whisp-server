#pragma once

#include "whisp-protobuf/cpp/client.pb.h"
#include "whisp-protobuf/cpp/server.pb.h"
#include "whisp-server/channel.h"
#include "whisp-server/command.h"
#include "whisp-server/connection.h"

#include <map>
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
  void cleanup();

private:
  void initialize_ssl_context();
  std::string get_supported_cipher_list();

  virtual void handle_connection(Connection *conn);
  void send_message(const google::protobuf::Message &msg, Connection conn);
  void broadcast(const google::protobuf::Message &msg,
                 std::string target_channel);
  void close_connection(Connection *conn);

  server::Status get_server_status();
  server::Message create_message(server::Message::MessageType type,
                                 std::string content);

  bool parse_command(Connection *conn, Command cmd);
  bool parse_login_command(Connection *conn, std::vector<std::string> args);
  bool parse_register_command(Connection *conn, std::vector<std::string> args);
  bool parse_set_command(Connection *conn, std::vector<std::string> args);
  bool parse_create_command(Connection *conn, std::vector<std::string> args);
  bool parse_join_command(Connection *conn, std::vector<std::string> args);

  const std::string &host;
  int port;
  std::size_t max_conn;
  std::map<std::string, Channel> channels;

  std::string cert_path;
  std::string key_path;
  SSL_CTX *ssl_ctx = nullptr;

  int serv_fd;
  struct sockaddr_in serv_addr;

  std::unordered_set<Connection *, ConnectionHash> connections;
};
