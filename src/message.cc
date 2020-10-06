#include "whisp-server/message.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>

Message::Message(Connection conn, std::string message)
    : conn(conn), message(message) {
  if (this->message.front() == '/') {
    is_command = true;

    // message is command, split message by space and save parts
    split_message_parts();
  }
}

std::string Message::get_fmt_str() {
  return "[" + conn.username + "]: " + message;
}

void Message::split_message_parts() {
  std::istringstream iss(message);
  std::vector<std::string> result{std::istream_iterator<std::string>(iss), {}};
  message_parts = result;
}

Command Message::get_command() {
  std::string command_str = message_parts.front();
  command_str.erase(0, 1);
  std::transform(command_str.begin(), command_str.end(), command_str.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  CommandType type;
  std::vector<std::string> args = {message_parts.begin() + 1,
                                   message_parts.end()};
  std::unordered_map<std::string, CommandType>::iterator it =
      commands_map.find(command_str);

  if (it != commands_map.end()) {
    type = it->second;
  } else {
    type = Unknown;
  }

  return {type, args};
}
