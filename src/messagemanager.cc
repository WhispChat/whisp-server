#include "whisp-server/messagemanager.h"

#include <google/protobuf/any.pb.h>

void MessageManager::send_message(const google::protobuf::Message &msg,
                                  Connection conn) {
  google::protobuf::Any any;
  any.PackFrom(msg);

  std::string msg_str;
  any.SerializeToString(&msg_str);

  SSL_write(conn.ssl, msg_str.data(), msg_str.size());
}

void MessageManager::broadcast(const google::protobuf::Message &msg) {
  for (auto conn : connections) {
    send_message(msg, *conn);
  }
}

server::Message
MessageManager::create_message(server::Message::MessageType type,
                               std::string content) {
  server::Message msg;
  msg.set_type(type);
  msg.set_content(content);

  return msg;
}

std::string MessageManager::get_supported_cipher_list(SSL_CTX *ssl_ctx) {
  std::string cipher_list;

  STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ssl_ctx);
  for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    cipher_list +=
        std::string(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i))) +
        ", ";
  }

  return cipher_list.substr(0, cipher_list.size() - 2);
}

void MessageManager::welcome_message(User *user, Connection *conn) {
  // Broadcast a message to all existing connections to inform about the
  // new connection
  std::string user_joined_message = user->username + " has joined the channel.";
  broadcast(create_message(server::Message::INFO, user_joined_message));

  // Send a welcome message to the new connection
  std::string welcome_message =
      "Welcome to the channel, " + user->username + "!";
  send_message(create_message(server::Message::INFO, welcome_message), *conn);

  // Send a message containing a list of all existing users to the new
  // connection
  std::string user_list_message;
  if (connections.empty()) {
    user_list_message = "There are no users in this channel.";
  } else {
    user_list_message = "Users in this channel: " + get_users_list() + ".";
  }
  send_message(create_message(server::Message::INFO, user_list_message), *conn);
}

std::string MessageManager::get_users_list() {
  std::string user_list_message;

  for (auto conn : connections) {
    user_list_message += conn->user->display_name() + ", ";
  }
  return user_list_message.substr(0, user_list_message.size() - 2);
}