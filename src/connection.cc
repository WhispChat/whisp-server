#include "whisp-server/connection.h"
#include "whisp-server/logging.h"

#include <google/protobuf/any.pb.h>
#include <thread>

Connection::Connection(User *user, struct sockaddr_in addr, socklen_t addr_len,
                       int fd, SSL *ssl, TCPSocketServer socketserver) {
  std::thread t(&Connection::handle_connection, socketserver);
  t.detach();
}

void Connection::set_user(User *new_user) {
  if (this->user) {
    delete this->user;
  }
  this->user = new_user;
}

void Connection::send_message(const google::protobuf::Message &msg) {
  google::protobuf::Any any;
  any.PackFrom(msg);

  std::string msg_str;
  any.SerializeToString(&msg_str);

  SSL_write(this->ssl, msg_str.data(), msg_str.size());
}

void Connection::handle_connection(TCPSocketServer socketserver) {
  char buffer[4096];

  while (SSL_read(this->ssl, buffer, sizeof buffer) > 0) {
    std::string str_buffer(buffer);

    client::Message user_msg;
    user_msg.ParseFromString(str_buffer);

    if (Command::is_command(user_msg.content())) {
      Command cmd(user_msg.content());
      bool close_conn = socketserver.parse_command(this, cmd);
      if (close_conn) {
        break;
      }
    } else {
      this->user->set_message_data(user_msg);

      LOG_DEBUG << this->user->display_name() << ": " << user_msg.content()
                << '\n';

      socketserver.broadcast(user_msg);
    }

    memset(buffer, 0, sizeof buffer);
  }

  socketserver.cleanup_one(this);
}
