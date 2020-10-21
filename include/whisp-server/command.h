#pragma once

#include <string>
#include <vector>

class Command {
public:
  Command(std::string message);

  static bool is_command(std::string message);

  std::string type;
  std::vector<std::string> args;

private:
  std::vector<std::string> split_message_parts();

  std::string message;
};
