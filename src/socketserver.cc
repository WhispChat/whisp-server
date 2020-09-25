#include "whisp-server/socketserver.h"

#include <iostream>

void TCPSocketServer::initialize() {
  serv_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (serv_fd == -1) {
    throw "socket failed";
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(host.c_str());
  serv_addr.sin_port = htons(port);

  int reuse_port = 1;
  int ret_test =
      setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_port, sizeof(int));

  if (ret_test == -1) {
    throw "setsockopt failed";
  }

  int bind_ret =
      bind(serv_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

  if (bind_ret == -1) {
    throw "bind failed";
  }

  int listen_ret = listen(serv_fd, max_conn);

  if (listen_ret == -1) {
    throw "listen failed";
  }
}

void TCPSocketServer::serve() {
  std::cout << "[INFO] Listening on " << host << ":" << port << std::endl;

  while (1) {
    int client_fd = -1;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    ::listen(serv_fd, max_conn);

    if (connections.size() < max_conn) {
      // Accept connection if we're not at max connections
      client_fd = accept(serv_fd, (struct sockaddr *)&client_addr, &client_len);

      if (client_fd == -1) {
        std::cout << "[ERROR] failed to connect to incoming connection"
                  << std::endl;
        continue;
      }

      std::string username = "user" + std::to_string(connections.size());
      Connection conn(username, client_addr, client_len, client_fd);
      connections.insert(conn);

      std::cout << "[INFO] new connection " << conn << std::endl;

      std::thread t(&TCPSocketServer::handle_connection, this, conn);
      t.detach();
    }
  }
}

void TCPSocketServer::handle_connection(Connection conn) {
  // TODO: more C++ way of reading to buffer using iostream?
  char buffer[4096];
  std::string username = "[" + conn.username + "]: ";
  size_t username_size = username.size();

  memcpy(buffer, username.data(), username_size);

  while (recv(conn.fd, buffer + username_size, sizeof buffer, 0) > 0) {
    for (auto client : connections) {
      send(client.fd, (void *)buffer, strlen(buffer), MSG_NOSIGNAL);
    }

    std::cout << buffer << std::endl;

    bzero(buffer, sizeof buffer);
    memcpy(buffer, username.data(), username_size);
  }

  std::cout << "[INFO] connection " << conn << " disconnected" << std::endl;

  connections.erase(conn);
  close(conn.fd);
}

TCPSocketServer::~TCPSocketServer() { close(serv_fd); }
