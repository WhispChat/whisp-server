#include "whisp-server/socketserver.h"
#include "whisp-server/connection.h"
#include "whisp-server/encryption.h"
#include "whisp-server/logging.h"
#include "whisp-server/user.h"

#include <algorithm>
#include <google/protobuf/any.pb.h>
#include <google/protobuf/repeated_field.h>
#include <iostream>
#include <regex>
#include <string.h>
#include <string>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>

// Standardized regular expression checking for valid e-mail address
const std::regex email_regex("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}$",
                             std::regex_constants::icase);

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
  LOG_DEBUG << "Max connections: " << max_conn << '\n';
  LOG_DEBUG << "Server file descriptor: " << serv_fd << '\n';

  while (1) {
    int client_fd = -1;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    client_fd = accept(serv_fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_fd == -1) {
      LOG_ERROR << "Failed to connect to incoming connection\n";
      continue;
    }

    // Currently, new connections will default to guest users - an
    // authentication flow for registered users should be added alongside GUI
    // TODO: Better user id assignment
    GuestUser user("guest" + std::to_string(connections.size()));
    Connection *new_conn =
        new Connection(user, client_addr, client_len, client_fd);

    // Always send server status to new client even when max connections is
    // reached so client knows the server is full
    send_message(get_server_status(), *new_conn);

    if (connections.size() >= max_conn) {
      // Deny connection if we're at max connections
      LOG_DEBUG << "Denying new connection " << *new_conn << ": server full."
                << '\n';
      close_connection(new_conn);
      continue;
    }

    // Broadcast a message to all existing connections to inform about the
    // new connection
    std::string user_joined_message =
        user.username + " has joined the channel.";
    broadcast(create_message(server::Message::INFO, user_joined_message));

    // Send a welcome message to the new connection
    std::string welcome_message =
        "Welcome to the channel, " + user.username + "!";
    send_message(create_message(server::Message::INFO, welcome_message),
                 *new_conn);

    LOG_INFO << "New connection " << *new_conn << '\n';
    connections.insert(new_conn);

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

    std::thread t(&TCPSocketServer::handle_connection, this, new_conn);
    t.detach();
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

    client::Message user_msg;
    user_msg.ParseFromString(decrypted_buffer);

    if (Command::is_command(user_msg.content())) {
      Command cmd(user_msg.content());
      bool close_conn = parse_command(conn, cmd);
      if (close_conn) {
        break;
      }
    } else {
      user_msg.set_username(conn->user.username);

      broadcast(user_msg);

      LOG_DEBUG << user_msg.username() << ": " << user_msg.content() << '\n';
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

// TODO: Given the method's size, this may have to be refactored into its own
// class
bool TCPSocketServer::parse_command(Connection *conn, Command cmd) {
  std::vector<std::string> args = cmd.args;
  std::string type = cmd.type;

  if (type.compare("quit") == 0) {
    return true;
  } else if (type.compare("login") == 0) {
    if (args.size() != 2) {
      std::string error_msg = "Incorrect amount of arguments for set - "
                              "expected 2 (username, password).";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
      return false;
    }

    std::string username = args.at(0);
    // TODO: Password is not considered for now
    std::string password = args.at(1);

    for (auto user : registered_users) {
      if (user->username == username) {
        RegisteredUser *found_user = user;
        conn->set_user(*found_user);
        std::string login_message =
            "You are now logged in as " + found_user->username;
        send_message(create_message(server::Message::INFO, login_message),
                     *conn);
        LOG_INFO << "Connection " << *conn << " has changed auth" << '\n';
        return false;
      }
    }

    std::string error_msg = "Unable to login as " + username;
    send_message(create_message(server::Message::ERROR, error_msg), *conn);
  } else if (type.compare("register") == 0) {
    if (args.size() != 3) {
      std::string error_msg = "Incorrect amount of arguments for set - "
                              "expected 3 (username, email, password).";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
      return false;
    }

    std::string username = args.at(0);
    std::string email = args.at(1);
    std::string password = args.at(2);

    if (!std::regex_match(email, email_regex)) {
      std::string error_msg =
          "The e-mail address provided does not appear to be valid";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
      return false;
    }

    // TODO: More robust password validation, such as minimum amount of letters,
    // numbers, symbols...
    if (password.length() < 8) {
      std::string error_msg =
          "Passwords should be minimally eight characters long";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
      return false;
    }

    RegisteredUser *new_user = new RegisteredUser(username, email, password);
    registered_users.insert(new_user);

    conn->set_user(*new_user);
    std::string registration_message =
        "You have created, and are now logged in as " + new_user->username;
    send_message(create_message(server::Message::INFO, registration_message),
                 *conn);
    LOG_INFO << "Connection " << *conn << " has changed auth" << '\n';
  } else if (type.compare("set") == 0) {
    if (args.size() != 2) {
      std::string error_msg = "Incorrect amount of arguments for set - "
                              "expected 2 (key, value).";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
      return false;
    }

    std::string set_variable = args.at(0);
    std::string set_value = args.at(1);

    // make set variable case insensitive
    std::transform(set_variable.begin(), set_variable.end(),
                   set_variable.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (set_variable.compare("username") == 0) {
      std::string old_username = conn->user.username;
      conn->user.set_username(set_value);
      std::string username_message = old_username +
                                     " changed their username to " +
                                     conn->user.username + ".";

      LOG_DEBUG << username_message << '\n';
      broadcast(create_message(server::Message::INFO, username_message));
    } else {
      std::string error_msg = "Unknown variable \"" + set_variable + "\".";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
    }
  } else if (type.compare("users") == 0) {
    std::string user_list_message =
        "Users in this channel: " + get_users_list() + ".";
    send_message(create_message(server::Message::INFO, user_list_message),
                 *conn);

  } else {
    std::string error_msg = "Unknown command";

    send_message(create_message(server::Message::ERROR, error_msg), *conn);
  }

  return false;
}

void TCPSocketServer::close_connection(Connection *conn) {
  LOG_INFO << "Connection " << *conn << " disconnected" << '\n';

  close(conn->fd);
  connections.erase(conn);
  delete conn;
}

std::string TCPSocketServer::get_users_list() {
  std::string user_list_message;

  for (auto conn : connections) {
    user_list_message += conn->user.username + ", ";
  }
  return user_list_message.substr(0, user_list_message.size() - 2);
}

server::Status TCPSocketServer::get_server_status() {
  server::Status status;
  status.set_max_connections(max_conn);
  status.set_number_connections(connections.size());

  return status;
}

server::Message
TCPSocketServer::create_message(server::Message::MessageType type,
                                std::string content) {
  server::Message msg;
  msg.set_type(type);
  msg.set_content(content);

  return msg;
}
