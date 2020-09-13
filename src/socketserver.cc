#include "whisp-server/socketserver.h"

void TCPSocketServer::initialize() {
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd == -1) {
    throw "socket failed";
  }

  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(host.c_str());
  serv_addr.sin_port = htons(port);

  int reuse_port = 1;
  int ret_test =
      setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_port, sizeof(int));

  if (ret_test == -1) {
    throw "setsockopt failed";
  }

  int bind_ret =
      bind(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

  if (bind_ret == -1) {
    throw "bind failed";
  }

  int listen_ret = listen(sock_fd, max_conn);

  if (listen_ret == -1) {
    throw "listen failed";
  }
}

void TCPSocketServer::serve() {
  std::cout << "[INFO] Listening on " << host << ":" << port << std::endl;

  while (1) {
    int client_sock_fd = -1;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    ::listen(sock_fd, max_conn);
    client_sock_fd =
        accept(sock_fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_sock_fd == -1) {
      throw "failed to connect to incoming connection";
    }

    std::thread t(&TCPSocketServer::handle_connection, this, client_sock_fd);
    t.detach();
  }
}

void TCPSocketServer::handle_connection(int client_sock_fd) {
  char buffer[256];
  const char *response = "ack\n";

  while (recv(client_sock_fd, buffer, 255, 0) > 0) {
    std::cout << buffer;
    send(client_sock_fd, (void *)response, strlen(response), MSG_NOSIGNAL);
    bzero(buffer, 256);
  }

  close(client_sock_fd);
}

TCPSocketServer::~TCPSocketServer() { close(sock_fd); }
