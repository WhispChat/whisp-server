#include "whisp-server/socketserver.h"
#include "whisp-server/connection.h"
#include "whisp-server/db.h"
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
#include <openssl/err.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>

// Standardized regular expression checking for valid e-mail address
const std::regex
    email_regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}$",
                std::regex_constants::icase);

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

std::string TCPSocketServer::get_supported_cipher_list() {
  std::string cipher_list;

  STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ssl_ctx);
  for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    cipher_list +=
        std::string(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i))) +
        ", ";
  }

  return cipher_list.substr(0, cipher_list.size() - 2);
}

void TCPSocketServer::serve() {
  LOG_INFO << "Listening on " << host << ":" << port << '\n';
  LOG_DEBUG << "Max connections: " << max_conn << '\n';
  LOG_DEBUG << "Server file descriptor: " << serv_fd << '\n';
  LOG_DEBUG << "Supported ciphers: " << get_supported_cipher_list() << '\n';

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
        new GuestUser("user" + std::to_string(connections.size()));
    Connection *new_conn =
        new Connection(user, client_addr, client_len, client_fd, ssl);

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
        user->username + " has joined the channel.";
    broadcast(create_message(server::Message::INFO, user_joined_message));

    // Send a welcome message to the new connection
    std::string welcome_message =
        "Welcome to the channel, " + user->username + "!";
    send_message(create_message(server::Message::INFO, welcome_message),
                 *new_conn);

    LOG_INFO << "New connection " << *new_conn << " using cipher "
             << SSL_get_cipher(ssl) << '\n';
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
  server::ServerClosed closed_msg;

  // send closed message to client which will close the client's respective
  // thread and call close_connection().
  for (auto conn : connections) {
    send_message(closed_msg, *conn);
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
      Command cmd(user_msg.content());
      bool close_conn = parse_command(conn, cmd);
      if (close_conn) {
        break;
      }
    } else {
      conn->user->set_message_data(user_msg);

      LOG_DEBUG << conn->user->display_name() << ": " << user_msg.content()
                << '\n';

      broadcast(user_msg);
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

  SSL_write(conn.ssl, msg_str.data(), msg_str.size());
}

void TCPSocketServer::broadcast(const google::protobuf::Message &msg) {
  for (auto conn : connections) {
    send_message(msg, *conn);
  }
}

void TCPSocketServer::close_connection(Connection *conn) {
  LOG_INFO << "Connection " << *conn << " disconnected" << '\n';

  SSL_shutdown(conn->ssl);
  close(conn->fd);
  SSL_free(conn->ssl);

  connections.erase(conn);

  delete conn->user;
  delete conn;
}

std::string TCPSocketServer::get_users_list() {
  std::string user_list_message;

  for (auto conn : connections) {
    user_list_message += conn->user->display_name() + ", ";
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

bool TCPSocketServer::parse_command(Connection *conn, Command cmd) {
  std::vector<std::string> args = cmd.args;
  std::string type = cmd.type;

  if (type.compare("quit") == 0) {
    return true;
  } else if (type.compare("login") == 0) {
    return parse_login_command(conn, args);
  } else if (type.compare("register") == 0) {
    return parse_register_command(conn, args);
  } else if (type.compare("set") == 0) {
    return parse_set_command(conn, args);
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

bool TCPSocketServer::parse_login_command(Connection *conn,
                                          std::vector<std::string> args) {
  if (args.size() != 2) {
    std::string error_msg = "Incorrect amount of arguments for set - "
                            "expected 2 (username, password).";
    send_message(create_message(server::Message::ERROR, error_msg), *conn);
    return false;
  }

  std::string username = args.at(0);
  std::string password = args.at(1);

  RegisteredUser *found_user = db::user::get(username);
  // TODO: check password hash
  if (!found_user || !found_user->check_password(password)) {
    send_message(create_message(server::Message::ERROR, "Incorrect login."),
                 *conn);
    return false;
  }

  conn->set_user(found_user);
  std::string login_message =
      "You are now logged in as " + found_user->username;
  send_message(create_message(server::Message::INFO, login_message), *conn);

  LOG_INFO << "Connection " << *conn << " has changed auth" << '\n';

  return false;
}

bool TCPSocketServer::parse_register_command(Connection *conn,
                                             std::vector<std::string> args) {
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

  // TODO: More robust password validation, such as minimum amount of
  // letters, numbers, symbols...
  if (password.length() < 8) {
    std::string error_msg =
        "Passwords should be minimally eight characters long";
    send_message(create_message(server::Message::ERROR, error_msg), *conn);
    return false;
  }

  try {
    RegisteredUser *new_user = db::user::add(username, email, password);

    if (new_user) {
      conn->set_user(new_user);
      std::string registration_message =
          "You have been registered, and are now logged in as " +
          new_user->username;
      send_message(create_message(server::Message::INFO, registration_message),
                   *conn);
      LOG_INFO << "Connection " << *conn << " has changed auth\n";
    } else {
      // SQLite error, inform user
      std::string error_msg = "Registration process failed, please "
                              "check with server administrator(s).";
      send_message(create_message(server::Message::ERROR, error_msg), *conn);
    }
  } catch (char const *error_msg) {
    send_message(create_message(server::Message::ERROR, error_msg), *conn);
  }

  return false;
}

bool TCPSocketServer::parse_set_command(Connection *conn,
                                        std::vector<std::string> args) {
  if (args.size() != 2) {
    std::string error_msg = "Incorrect amount of arguments for set - "
                            "expected 2 (key, value).";
    send_message(create_message(server::Message::ERROR, error_msg), *conn);
    return false;
  }

  std::string set_variable = args.at(0);
  std::string set_value = args.at(1);

  // make set variable case insensitive
  std::transform(set_variable.begin(), set_variable.end(), set_variable.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (set_variable.compare("username") == 0) {
    std::string old_username = conn->user->username;
    conn->user->set_username(set_value);
    std::string username_message = old_username +
                                   " changed their username to " +
                                   conn->user->username + ".";

    LOG_DEBUG << username_message << '\n';
    broadcast(create_message(server::Message::INFO, username_message));
  } else {
    std::string error_msg = "Unknown variable \"" + set_variable + "\".";
    send_message(create_message(server::Message::ERROR, error_msg), *conn);
  }

  return false;
}
