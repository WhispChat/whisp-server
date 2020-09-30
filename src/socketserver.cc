#include "whisp-server/socketserver.h"
#include "whisp-server/connection.h"
#include "whisp-server/message.h"

#include <algorithm>
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
  std::cout << "[INFO] Listening on " << host << ":" << port << '\n';

  while (1) {
    int client_fd = -1;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    if (connections.size() < max_conn) {
      // Accept connection if we're not at max connections
      client_fd = accept(serv_fd, (struct sockaddr *)&client_addr, &client_len);

      if (client_fd == -1) {
        std::cout << "[ERROR] failed to connect to incoming connection" << '\n';
        continue;
      }

      std::string username = "user" + std::to_string(connections.size());
      Connection *new_conn =
              new Connection(username, client_addr, client_len, client_fd);
      // Send a message containing a list of all existing users to the new connection
      std::string user_list_message;
      if (connections.empty()) {
        user_list_message = "[INFO] There are no users in this channel.";
      } else {
        user_list_message = "[INFO] Users in this channel: ";
        for (auto conn : connections) {
          user_list_message += conn->username + ", ";
        }
        user_list_message = user_list_message.substr(0, user_list_message.size() - 2) + ".";
      }
      send_message(user_list_message, *new_conn);

      std::cout << "[INFO] new connection " << *new_conn << '\n';
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
    Message msg(*conn, buffer);

    if (msg.is_command) {
      Command cmd = msg.get_command();
      bool close_conn = parse_command(conn, cmd);
      if (close_conn) {
        break;
      }
    } else {
      std::string message_str = msg.get_fmt_str();

      broadcast(message_str);

      std::cout << message_str << '\n';
    }

    bzero(buffer, sizeof buffer);
  }

  close_connection(conn);
}

void TCPSocketServer::send_message(std::string msg, Connection conn) {
  send(conn.fd, msg.data(), msg.size(), MSG_NOSIGNAL);
}

void TCPSocketServer::broadcast(std::string msg) {
  for (auto conn : connections) {
    send(conn->fd, msg.data(), msg.size(), MSG_NOSIGNAL);
  }
}

bool TCPSocketServer::parse_command(Connection *conn, Command cmd) {
  switch (cmd.type) {
  case CloseConnection:
    return true;
    break;
  case Set: {
    std::string set_variable = cmd.args.at(0);
    std::string set_value = cmd.args.at(1);

    // make set variable case insensitive
    std::transform(set_variable.begin(), set_variable.end(),
                   set_variable.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (set_variable.compare("username") == 0) {
      conn->set_username(set_value);
    } else {
      std::stringstream error_stream;
      error_stream << "unknown variable \"" << set_variable << "\"\n";
      std::string error_msg = error_stream.str();
      send(conn->fd, error_msg.data(), error_msg.size(), MSG_NOSIGNAL);
    }
    break;
  }
  case ListUsers: {
    std::stringstream connected_users;
    connected_users << "Connected users: ";
    for (auto user : connections) {
      connected_users << user->username << " ";
    }
    connected_users << '\n';

    std::string connected_users_str = connected_users.str();
    send(conn->fd, connected_users_str.data(), connected_users_str.size(),
         MSG_NOSIGNAL);

    break;
  }
  case Unknown: {
    std::string error_msg = "unknown command\n";
    send(conn->fd, error_msg.data(), error_msg.size(), MSG_NOSIGNAL);
    break;
  }
  }
  return false;
}

void TCPSocketServer::close_connection(Connection *conn) {
  std::cout << "[INFO] closing connection " << *conn << '\n';

  close(conn->fd);
  connections.erase(conn);
  delete conn;
}
