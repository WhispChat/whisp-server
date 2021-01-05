#pragma once

#include "whisp-protobuf/cpp/server.pb.h"
#include "whisp-server/connection.h"

class MessageManager {
public:
  MessageManager(std::unordered_set<Connection *, ConnectionHash> &_connections)
      : connections(_connections) {}

  void broadcast(const google::protobuf::Message &msg);
  void send_message(const google::protobuf::Message &msg, Connection conn);
  server::Message create_message(server::Message::MessageType type,
                                 std::string content);

  std::string get_supported_cipher_list(SSL_CTX *ssl_ctx);
  void welcome_message(User *user, Connection *conn);
  std::string get_users_list();

private:
  std::unordered_set<Connection *, ConnectionHash> connections;
};
