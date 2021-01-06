#include "whisp-server/command.h"
#include "whisp-server/db.h"
#include "whisp-server/hashing.h"
#include "whisp-server/logging.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <iterator>
#include <regex>
#include <sstream>
#include <string>

// Standardized regular expression checking for valid e-mail address
const std::regex
    email_regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}$",
                std::regex_constants::icase);

Command::Command(std::string message, MessageManager *_message_manager,
                 std::unordered_set<Connection *, ConnectionHash> &_connections,
                 std::map<std::string, Channel *> &_channels)
    : message(message), message_manager(_message_manager),
      connections(_connections), channels(_channels) {
  std::vector<std::string> message_parts = split_message_parts();

  type = message_parts.front();
  type.erase(0, 1);
  std::transform(type.begin(), type.end(), type.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  args = {message_parts.begin() + 1, message_parts.end()};
}

bool Command::is_command(std::string message) { return message.front() == '/'; }

std::vector<std::string> Command::split_message_parts() {
  std::istringstream iss(message);
  std::vector<std::string> result{std::istream_iterator<std::string>(iss), {}};
  return result;
}

bool Command::parse_command(Connection *conn) {
  if (type.compare("quit") == 0) {
    return true;
  } else if (type.compare("login") == 0) {
    login_command(conn);
  } else if (type.compare("register") == 0) {
    register_command(conn);
  } else if (type.compare("set") == 0) {
    set_command(conn);
  } else if (type.compare("users") == 0) {
    users_command(conn);
  } else if (type.compare("channels") == 0) {
    channels_command(conn);
  } else if (type.compare("create") == 0) {
    create_channel_command(conn);
  } else if (type.compare("join") == 0) {
    join_channel_command(conn);
  } else {
    std::string error_msg = "Unknown command";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
  }

  return false;
}

void Command::login_command(Connection *conn) {
  if (args.size() != 2) {
    std::string error_msg = "Incorrect amount of arguments for set - "
                            "expected 2 (username, password).";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
  }

  std::string username = args.at(0);
  std::string password = args.at(1);

  try {
    RegisteredUser *found_user = db::user::get(username);
    if (*conn->user == *found_user) {
      std::string logged_in_msg = "You are already logged in as this user.";
      message_manager->create_and_send(server::Message::INFO, logged_in_msg,
                                       conn);
      return;
    }

    if (!found_user || !found_user->compare_hash(password)) {
      message_manager->create_and_send(server::Message::ERROR,
                                       "Incorrect login.", conn);
      return;
    }

    auto user_already_authenticated =
        std::find_if(connections.begin(), connections.end(),
                     [found_user](Connection *conn_iteratee) {
                       return *conn_iteratee->user == *found_user;
                     });
    if (user_already_authenticated != connections.end()) {
      std::string error_msg =
          "This user is already logged in on another client.";
      message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
      return;
    }

    Channel *current_channel = channels.at(conn->channel->name);
    current_channel->remove_user(conn->user->display_name());
    conn->set_user(found_user);
    current_channel->add_user(conn->user->display_name());

    std::string login_message =
        "You are now logged in as " + found_user->username + ".";
    message_manager->create_and_send(server::Message::INFO, login_message,
                                     conn);

    LOG_INFO << "Connection " << *conn << " has changed auth" << '\n';
  } catch (const std::exception &ex) {
    message_manager->create_and_send(server::Message::ERROR, ex.what(), conn);
  }
}

void Command::register_command(Connection *conn) {
  if (args.size() != 3) {
    std::string error_msg = "Incorrect amount of arguments for set - "
                            "expected 3 (username, email, password).";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
  }

  std::string username = args.at(0);
  std::string email = args.at(1);
  std::string password = args.at(2);

  if (!std::regex_match(email, email_regex)) {
    std::string error_msg =
        "The e-mail address provided does not appear to be valid";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
  }

  // TODO: More robust password validation, such as minimum amount of
  // letters, numbers, symbols...
  if (password.length() < 8) {
    std::string error_msg =
        "Passwords should be minimally eight characters long";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
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
      message_manager->create_and_send(server::Message::INFO,
                                       registration_message, conn);
      LOG_INFO << "Connection " << *conn << " has changed auth\n";
    } else {
      // SQLite error, inform user
      std::string error_msg = "Registration process failed, please "
                              "check with server administrator(s).";
      message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    }
  } catch (const std::exception &ex) {
    message_manager->create_and_send(server::Message::ERROR, ex.what(), conn);
  }
}

void Command::set_command(Connection *conn) {
  if (args.size() != 2) {
    std::string error_msg = "Incorrect amount of arguments for set - "
                            "expected 2 (key, value).";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
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
    message_manager->broadcast(message_manager->create_message(
                                   server::Message::INFO, username_message),
                               conn->channel->name);
  } else {
    std::string error_msg = "Unknown variable \"" + set_variable + "\".";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
  }
}

void Command::users_command(Connection *conn) {
  auto users_list = channels.at(conn->channel->name)->get_users_list();
  std::string user_list_message = "Users in this channel: " + users_list + ".";
  message_manager->create_and_send(server::Message::INFO, user_list_message,
                                   conn);
}

void Command::channels_command(Connection *conn) {
  std::string channel_list_message = "Available public channels: ";
  std::vector<Channel> channel_list = db::channel::get_all();
  for (auto channel : channel_list) {
    channel_list_message += channel.name + " ";
  }

  message_manager->create_and_send(server::Message::INFO, channel_list_message,
                                   conn);
}

void Command::create_channel_command(Connection *conn) {
  // Return an error if the first parameter isn't 'channel'
  if (args.size() >= 0 && args.at(0) != "channel") {
    std::string error_msg = "Unknown command";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
  }

  if (!conn->user->is_registered()) {
    std::string error_msg = "You are not allowed to create channels. "
                            "Please register or login and try again.";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
  }

  int max_users;
  if (args.size() == 2) {
    max_users = 8;
  } else if (args.size() == 3) {
    try {
      max_users = std::stoi(args.at(2));
    } catch (const std::exception &ex) {
      std::string error_msg =
          "Incorrect type of arguments for create channel - "
          "expected at least 1 (channel name, max users [numbers only, "
          "default: 8]).";
      message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
      return;
    }
  } else {
    std::string error_msg =
        "Incorrect amount of arguments for create channel - "
        "expected at least 1 (channel name, max users [numbers only, default: "
        "8]).";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
  }

  // Make channel name case insensitive
  std::string channel_name = args.at(1);
  std::transform(channel_name.begin(), channel_name.end(), channel_name.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Check if channel name is in use
  Channel *duplicate_channel = db::channel::get(channel_name);

  if (duplicate_channel) {
    // Channel name most likely already in use, inform user
    std::string error_msg = "Channel name \"" + channel_name +
                            "\" is already in use. Please choose another name.";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
  } else {
    // Channel name is not in use, create new channel
    Channel *new_channel =
        db::channel::add(channel_name, conn->user->user_id, max_users);
    if (new_channel) {
      std::string success_message =
          "Channel \"" + channel_name + "\" succesfully created.";

      LOG_DEBUG << success_message << '\n';
      message_manager->create_and_send(server::Message::INFO, success_message,
                                       conn);
    } else {
      // SQLite error, inform user
      std::string error_msg = "Creating channel failed, please "
                              "check with server administrator(s).";
      message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    }
  }
}

void Command::join_channel_command(Connection *conn) {
  // Return an error if the amount of parameters is incorrect
  if (args.size() != 1) {
    std::string error_msg = "Incorrect amount of arguments for join - "
                            "expected 1 (channel name).";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
  }

  // Check if the target channel exists
  Channel *target_channel = db::channel::get(args.at(0));
  if (target_channel) {
    // Retrieve channel from channels list if it's already active
    if (channels.count(target_channel->name)) {
      target_channel = channels.at(target_channel->name);

      // Return an error if the target channel is full
      if (target_channel->get_connection_amount() ==
          target_channel->max_users) {
        std::string error_msg = "Channel \"" + target_channel->name +
                                "\" is full. Please try again later.";
        message_manager->create_and_send(server::Message::ERROR, error_msg,
                                         conn);
      }
    }
  } else {
    // Return an error if the target channel does not exist
    std::string error_msg = "Channel \"" + args.at(0) + "\" does not exist.";
    message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
    return;
  }

  if (conn->channel) {
    Channel current_channel = *channels.at(conn->channel->name);

    // Return an error if the user is already in the target channel
    if (target_channel->name.compare(current_channel.name) == 0) {
      std::string error_msg =
          "You're already in channel \"" + target_channel->name + "\".";
      message_manager->create_and_send(server::Message::ERROR, error_msg, conn);
      return;
    }

    // Remove the connection from the current channel
    current_channel.remove_user(conn->user->display_name());

    // Check if the channel is now empty, if so: remove channel from list
    if (current_channel.get_connection_amount() == 0) {
      channels.erase(current_channel.name);
    } else {
      // Overwrite the channel object to save any changes made
      channels.extract(current_channel.name);
      channels.insert(std::make_pair(current_channel.name, &current_channel));

      // Inform all connections in the current channel about the connection
      // leaving
      std::string user_left_message =
          conn->user->display_name() + " has left the channel.";
      message_manager->broadcast(message_manager->create_message(
                                     server::Message::INFO, user_left_message),
                                 current_channel.name);
    }
  }

  // Add the connection to the target channel
  target_channel->add_user(conn->user->display_name());
  conn->set_channel(target_channel);

  message_manager->send_welcome_message(conn->user, conn);

  // Overwrite the channel object to save any changes made
  channels.insert(std::make_pair(target_channel->name, target_channel));
}
