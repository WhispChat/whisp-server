#pragma once

#include "whisp-server/connection.h"

#include "whisp-protobuf/cpp/server.pb.h"

namespace messaging {
void broadcast(const google::protobuf::Message &msg,
               std::unordered_set<Connection *, ConnectionHash> connections);
void send_message(const google::protobuf::Message &msg, Connection conn);
server::Message create_message(server::Message::MessageType type,
                               std::string content);

namespace helper {
std::string get_supported_cipher_list(SSL_CTX *ssl_ctx);
void welcome_message(
    User *user, Connection *conn,
    std::unordered_set<Connection *, ConnectionHash> connections);
std::string
get_users_list(std::unordered_set<Connection *, ConnectionHash> connections);
} // namespace helper
} // namespace messaging
