#pragma once

#include "whisp-protobuf/cpp/server.pb.h"
#include "whisp-server/connection.h"

class MessageManager {
public:
  MessageManager(std::unordered_set<Connection *, ConnectionHash> &_connections)
      : connections(_connections) {}

  void broadcast(const google::protobuf::Message &msg,
                 std::string channel_name);
  void send_message(const google::protobuf::Message &msg, Connection conn);
  void create_and_send(server::Message::MessageType type, std::string content,
                       Connection *conn);
  server::Message create_message(server::Message::MessageType type,
                                 std::string content);

  std::string get_supported_cipher_list(SSL_CTX *ssl_ctx);
  void send_welcome_message(Connection *conn);
  std::string get_users_list();

private:
  std::unordered_set<Connection *, ConnectionHash> &connections;
};
