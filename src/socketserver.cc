#include "whisp-server/socketserver.h"
#include "whisp-server/channel.h"
#include "whisp-server/command.h"
#include "whisp-server/db.h"
#include "whisp-server/logging.h"
#include "whisp-server/user.h"

#include <openssl/err.h>
#include <thread>
#include <unistd.h>
#include <vector>

void TCPSocketServer::initialize() {
  initialize_ssl_context();

  serv_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (serv_fd == -1) {
    throw std::string("socket failed");
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(host.c_str());
  serv_addr.sin_port = htons(port);

  int reuse_port = 1;
  if (setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_port, sizeof(int)) ==
      -1) {
    throw std::string("setsockopt failed");
  }

  if (bind(serv_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
    throw std::string("bind failed");
  }

  if (listen(serv_fd, max_conn) == -1) {
    throw std::string("listen failed");
  }

  message_manager = new MessageManager(connections);
}

void TCPSocketServer::initialize_ssl_context() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  const SSL_METHOD *method = SSLv23_server_method();
  ssl_ctx = SSL_CTX_new(method);
  if (!ssl_ctx) {
    ERR_print_errors_fp(stderr);
    throw std::string("Unable to create SSL context");
  }

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

  if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path.c_str(),
                                   SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path.c_str(),
                                  SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

void TCPSocketServer::serve() {
  LOG_INFO << "Listening on " << host << ":" << port << '\n';
  LOG_DEBUG << "Max connections: " << max_conn << '\n';
  LOG_DEBUG << "Server file descriptor: " << serv_fd << '\n';
  LOG_DEBUG << "Supported ciphers: "
            << message_manager->get_supported_cipher_list(ssl_ctx) << '\n';

  while (1) {
    int client_fd = -1;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL *ssl;

    client_fd = accept(serv_fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_fd == -1) {
      LOG_ERROR << "Failed to connect to incoming connection\n";
      continue;
    }

    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      continue;
    }

    // Currently, new connections will default to guest users - an
    // authentication flow for registered users should be added alongside GUI
    // TODO: Better user id assignment
    GuestUser *user =
        (GuestUser *)(new UserBuilder())
            ->set_username("user" + std::to_string(connections.size()))
            ->build();
    Connection *new_conn =
        new Connection(user, client_addr, client_len, client_fd, ssl);

    // Always send server status to new client even when max connections is
    // reached so client knows the server is full
    server::Status status;
    status.set_max_connections(max_conn);
    status.set_number_connections(connections.size());
    message_manager->send_message(status, *new_conn);

    if (connections.size() >= max_conn) {
      // Deny connection if we're at max connections
      LOG_DEBUG << "Denying new connection " << *new_conn
                << ": max global connections reached.\n";
      close_connection(new_conn);
      continue;
    }

    // Add the user to the general channel
    Command cmd("/join general", message_manager, connections, channels);
    cmd.parse_command(new_conn);

    LOG_INFO << "New connection " << *new_conn << " using cipher "
             << SSL_get_cipher(ssl) << '\n';
    connections.insert(new_conn);

    std::thread t(&TCPSocketServer::handle_connection, this, new_conn);
    t.detach();
  }
}

void TCPSocketServer::cleanup() {
  server::ServerClosed closed_msg;

  // send closed message to client which will close the client's respective
  // thread and call close_connection().
  for (auto conn : connections) {
    message_manager->send_message(closed_msg, *conn);
  }

  if (message_manager) {
    delete message_manager;
  }

  close(serv_fd);
  db::close_database();
  if (ssl_ctx) {
    SSL_CTX_free(ssl_ctx);
  }
}

void TCPSocketServer::handle_connection(Connection *conn) {
  char buffer[4096];

  while (SSL_read(conn->ssl, buffer, sizeof buffer) > 0) {
    std::string str_buffer(buffer);

    client::Message user_msg;
    user_msg.ParseFromString(str_buffer);

    if (Command::is_command(user_msg.content())) {
      Command cmd(user_msg.content(), message_manager, connections, channels);
      bool close_conn = cmd.parse_command(conn);
      if (close_conn) {
        break;
      }
    } else {
      conn->user->set_message_data(user_msg);

      LOG_DEBUG << conn->user->display_name() << ": " << user_msg.content()
                << '\n';

      message_manager->broadcast(user_msg, conn->channel->name);
    }

    memset(buffer, 0, sizeof buffer);
  }

  close_connection(conn);
}

void TCPSocketServer::close_connection(Connection *conn) {
  LOG_INFO << "Connection " << *conn << " disconnected" << '\n';

  channels.at(conn->channel->name)->remove_user(conn->user->display_name());

  SSL_shutdown(conn->ssl);
  close(conn->fd);
  SSL_free(conn->ssl);

  connections.erase(conn);

  delete conn->user;
  delete conn;
}
