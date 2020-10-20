#include "whisp-server/command.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>

Command::Command(std::string message) : message(message) {
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
