#include "whisp-server/commandmanager.h"
#include "whisp-server/db.h"
#include "whisp-server/hashing.h"
#include "whisp-server/logging.h"
#include "whisp-server/messaging.h"

#include <regex>

// Standardized regular expression checking for valid e-mail address
const std::regex
    email_regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}$",
                std::regex_constants::icase);

// Shorthand function for sending message to a specific connection
void send_and_create(server::Message::MessageType type, std::string content,
                     Connection *conn) {
  messaging::send_message(messaging::create_message(type, content), *conn);
}

// Prototype functions for convenience
bool login_command(Connection *conn, std::vector<std::string> args, std::unordered_set<Connection *, ConnectionHash> connections);
bool register_command(Connection *conn, std::vector<std::string> args);
bool set_command(Connection *conn, std::vector<std::string> args, std::unordered_set<Connection *, ConnectionHash> connections);
void users_command(Connection *conn, std::unordered_set<Connection *, ConnectionHash> connections);

namespace commandmanager {
bool parse_command(
    Connection *conn, Command cmd,
    std::unordered_set<Connection *, ConnectionHash> connections) {
  std::vector<std::string> args = cmd.args;
  std::string type = cmd.type;

  // TODO: Convert to switch statement
  if (type.compare("quit") == 0) {
    return true;
  } else if (type.compare("login") == 0) {
    login_command(conn, args, connections);
  } else if (type.compare("register") == 0) {
    register_command(conn, args);
  } else if (type.compare("set") == 0) {
    set_command(conn, args, connections);
  } else if (type.compare("users") == 0) {
    users_command(conn, connections);
  } else {
    std::string error_msg = "Unknown command";
    send_and_create(server::Message::ERROR, error_msg, conn);
  }

  return false;
}
} // namespace commandmanager

bool login_command(
    Connection *conn, std::vector<std::string> args,
    std::unordered_set<Connection *, ConnectionHash> connections) {
  if (args.size() != 2) {
    std::string error_msg = "Incorrect amount of arguments for set - "
                            "expected 2 (username, password).";
    send_and_create(server::Message::ERROR, error_msg, conn);
    return false;
  }

  std::string username = args.at(0);
  std::string password = args.at(1);

  try {
    RegisteredUser *found_user = db::user::get(username);
    if (*conn->user == *found_user) {
      std::string logged_in_msg = "You are already logged in as this user.";
      send_and_create(server::Message::INFO, logged_in_msg, conn);
      return false;
    }

    if (!found_user || !found_user->compare_hash(password)) {
      send_and_create(server::Message::ERROR, "Incorrect login.", conn);
      return false;
    }

    auto user_already_authenticated =
        std::find_if(connections.begin(), connections.end(),
                     [found_user](Connection *conn_iteratee) {
                       return *conn_iteratee->user == *found_user;
                     });
    if (user_already_authenticated != connections.end()) {
      std::string error_msg =
          "This user is already logged in on another client.";
      send_and_create(server::Message::ERROR, error_msg, conn);
      return false;
    }

    conn->set_user(found_user);
    std::string login_message =
        "You are now logged in as " + found_user->username + ".";
    send_and_create(server::Message::INFO, login_message, conn);

    LOG_INFO << "Connection " << *conn << " has changed auth" << '\n';
  } catch (const std::exception &ex) {
    send_and_create(server::Message::ERROR, ex.what(), conn);
  }

  return false;
}

bool register_command(Connection *conn, std::vector<std::string> args) {
  if (args.size() != 3) {
    std::string error_msg = "Incorrect amount of arguments for set - "
                            "expected 3 (username, email, password).";
    send_and_create(server::Message::ERROR, error_msg, conn);
    return false;
  }

  std::string username = args.at(0);
  std::string email = args.at(1);
  std::string password = args.at(2);

  if (!std::regex_match(email, email_regex)) {
    std::string error_msg =
        "The e-mail address provided does not appear to be valid";
    send_and_create(server::Message::ERROR, error_msg, conn);
    return false;
  }

  // TODO: More robust password validation, such as minimum amount of
  // letters, numbers, symbols...
  if (password.length() < 8) {
    std::string error_msg =
        "Passwords should be minimally eight characters long";
    send_and_create(server::Message::ERROR, error_msg, conn);
    return false;
  }

  try {
    std::string password_salt = hashing::generate_salt();
    std::string password_hash = hashing::hash_password(password, password_salt);
    RegisteredUser *new_user =
        db::user::add(username, email, password_hash, password_salt);

    if (new_user) {
      conn->set_user(new_user);
      std::string registration_message =
          "You have been registered, and are now logged in as " +
          new_user->username;
      send_and_create(server::Message::INFO, registration_message, conn);
      LOG_INFO << "Connection " << *conn << " has changed auth\n";
    } else {
      // SQLite error, inform user
      std::string error_msg = "Registration process failed, please "
                              "check with server administrator(s).";
      send_and_create(server::Message::ERROR, error_msg, conn);
    }
  } catch (const std::exception &ex) {
    send_and_create(server::Message::ERROR, ex.what(), conn);
  }

  return false;
}

bool set_command(Connection *conn, std::vector<std::string> args,
                 std::unordered_set<Connection *, ConnectionHash> connections) {
  if (args.size() != 2) {
    std::string error_msg = "Incorrect amount of arguments for set - "
                            "expected 2 (key, value).";
    send_and_create(server::Message::ERROR, error_msg, conn);
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
    messaging::broadcast(
        messaging::create_message(server::Message::INFO, username_message),
        connections);
  } else {
    std::string error_msg = "Unknown variable \"" + set_variable + "\".";
    send_and_create(server::Message::ERROR, error_msg, conn);
  }

  return false;
}

void users_command(
    Connection *conn,
    std::unordered_set<Connection *, ConnectionHash> connections) {
  std::string user_list_message =
      "Users in this channel: " +
      messaging::helper::get_users_list(connections) + ".";
  send_and_create(server::Message::INFO, user_list_message, conn);
}
