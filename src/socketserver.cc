#include "whisp-server/socketserver.h"
#include "whisp-server/connection.h"
#include "whisp-server/encryption.h"
#include "whisp-server/logging.h"
#include "whisp-server/message.h"

#include <algorithm>
#include <google/protobuf/any.pb.h>
#include <google/protobuf/timestamp.pb.h>
#include <iostream>
#include <string.h>
#include <string>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>

void TCPSocketServer::initialize() {
  serv_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (serv_fd == -1) {
    throw "socket failed";
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(host.c_str());
  serv_addr.sin_port = htons(port);

  int reuse_port = 1;
  if (setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_port, sizeof(int)) ==
      -1) {
    throw "setsockopt failed";
  }

  if (bind(serv_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
    throw "bind failed";
  }

  if (listen(serv_fd, max_conn) == -1) {
    throw "listen failed";
  }
}

void TCPSocketServer::serve() {
  LOG_INFO << "Listening on " << host << ":" << port << '\n';

  while (1) {
    int client_fd = -1;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    if (connections.size() < max_conn) {
      // Accept connection if we're not at max connections
      client_fd = accept(serv_fd, (struct sockaddr *)&client_addr, &client_len);

      if (client_fd == -1) {
        LOG_ERROR << "Failed to connect to incoming connection\n";
        continue;
      }

      std::string username = "user" + std::to_string(connections.size());
      Connection *new_conn =
          new Connection(username, client_addr, client_len, client_fd);

      send_message(get_server_status(), *new_conn);

      // Broadcast a message to all existing connections to inform about the
      // new connection
      std::string user_joined_message = username + " has joined the channel.";
      broadcast(create_message(server::Message::INFO, user_joined_message));

      // Send a welcome message to the new connection
      std::string welcome_message = "Welcome to the channel, " + username + "!";
      send_message(create_message(server::Message::INFO, welcome_message),
                   *new_conn);

      // Send a message containing a list of all existing users to the new
      // connection
      std::string user_list_message;
      if (connections.empty()) {
        user_list_message = "There are no users in this channel.";
      } else {
        user_list_message = "Users in this channel: " + get_users_list() + ".";
      }
      send_message(create_message(server::Message::INFO, user_list_message),
                   *new_conn);

      LOG_INFO << "New connection " << *new_conn << '\n';
      connections.insert(new_conn);

      std::thread t(&TCPSocketServer::handle_connection, this, new_conn);
      t.detach();
    }
  }
}

void TCPSocketServer::cleanup() {
  for (auto conn : connections) {
    close_connection(conn);
  }
  close(serv_fd);
}

void TCPSocketServer::handle_connection(Connection *conn) {
  char buffer[4096];

  while (recv(conn->fd, buffer, sizeof buffer, 0) > 0) {
    std::string decrypted_buffer(buffer);
    decrypted_buffer =
        Encryption::decrypt(decrypted_buffer, Encryption::OneTimePad);
    Message msg(*conn, decrypted_buffer);

    if (msg.is_command) {
      Command cmd = msg.get_command();
      bool close_conn = parse_command(conn, cmd);
      if (close_conn) {
        break;
      }
    } else {
      std::string message_str = msg.get_fmt_str();

      // TODO: protobuf for client messages
      // broadcast(message_str);

      LOG_DEBUG << message_str << '\n';
    }

    memset(buffer, 0, sizeof buffer);
  }

  close_connection(conn);
}

void TCPSocketServer::send_message(const google::protobuf::Message &msg,
                                   Connection conn) {
  google::protobuf::Any any;
  any.PackFrom(msg);

  std::string msg_str;
  any.SerializeToString(&msg_str);

  std::string encrypted_msg =
      Encryption::encrypt(msg_str, Encryption::OneTimePad);
  // Message receives ASCII character 23, "End of Trans. Block"
  // This is in case the TCP socket sends multiple messages in one packet
  // TODO: Perhaps the delimiter should also be encrypted
  encrypted_msg += 23;

  send(conn.fd, encrypted_msg.data(), encrypted_msg.size(), MSG_NOSIGNAL);
}

void TCPSocketServer::broadcast(const google::protobuf::Message &msg) {
  for (auto conn : connections) {
    send_message(msg, *conn);
  }
}

bool TCPSocketServer::parse_command(Connection *conn, Command cmd) {
  switch (cmd.type) {
  case CloseConnection:
    return true;
    break;
  case Set: {
    if (cmd.args.size() != 2) {
      std::string error_msg =
          "Incorrect amount of arguments for set - expected 2.";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
      break;
    }

    std::string set_variable = cmd.args.at(0);
    std::string set_value = cmd.args.at(1);

    // make set variable case insensitive
    std::transform(set_variable.begin(), set_variable.end(),
                   set_variable.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (set_variable.compare("username") == 0) {
      std::string old_username = conn->username;
      conn->set_username(set_value);
      std::string username_message =
          old_username + " changed their username to " + conn->username + ".";
      broadcast(create_message(server::Message::INFO, username_message));
    } else {
      std::string error_msg = "Unknown variable \"" + set_variable + "\".";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
    }
    break;
  }
  case ListUsers: {
    std::string user_list_message =
        "Users in this channel: " + get_users_list() + ".";
    send_message(create_message(server::Message::INFO, user_list_message),
                 *conn);

    break;
  }
  case Unknown: {
    std::string error_msg = "Unknown command";

    send_message(create_message(server::Message::ERROR, error_msg), *conn);
    break;
  }
  }
  return false;
}

void TCPSocketServer::close_connection(Connection *conn) {
  LOG_INFO << "Closing connection " << *conn << '\n';

  close(conn->fd);
  connections.erase(conn);
  delete conn;
}

std::string TCPSocketServer::get_users_list() {
  std::string user_list_message;

  for (auto conn : connections) {
    user_list_message += conn->username + ", ";
  }
  return user_list_message.substr(0, user_list_message.size() - 2);
}

server::Status TCPSocketServer::get_server_status() {
  server::Status status;
  status.set_full(connections.size() >= max_conn);
  status.set_number_connections(connections.size());

  google::protobuf::Timestamp timestamp;
  timestamp.set_seconds(time(NULL));
  timestamp.set_nanos(0);
  status.set_timestamp(timestamp);

  return status;
}

server::Message
TCPSocketServer::create_message(server::Message::MessageType type,
                                std::string content) {
  server::Message msg;
  msg.set_type(type);
  msg.set_content(content);

  google::protobuf::Timestamp timestamp;
  timestamp.set_seconds(time(NULL));
  timestamp.set_nanos(0);
  msg.set_timestamp(timestamp);

  return msg;
}

