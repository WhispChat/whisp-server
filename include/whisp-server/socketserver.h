#pragma once

#include "whisp-protobuf/cpp/client.pb.h"
#include "whisp-protobuf/cpp/server.pb.h"
#include "whisp-server/connection.h"
#include "whisp-server/messagemanager.h"

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
  virtual void handle_connection(Connection *conn);
  void close_connection(Connection *conn);

  const std::string &host;
  int port;
  std::size_t max_conn;

  std::string cert_path;
  std::string key_path;
  SSL_CTX *ssl_ctx = nullptr;

  int serv_fd;
  struct sockaddr_in serv_addr;

  MessageManager *message_manager;
  std::unordered_set<Connection *, ConnectionHash> connections;
  std::map<std::string, Channel *> channels;
};
