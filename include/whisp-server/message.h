#pragma once

#include "whisp-server/connection.h"

#include <vector>

enum CommandType { Set, CloseConnection, Unknown };

struct Command {
    CommandType type;
    std::vector<std::string> args;
};

class Message {
  public:
    Message(Connection conn, char *message);

    std::string get_fmt_str();
    Command get_command();

    std::string message;
    bool is_command = false;

  private:
    void split_message_parts();

    Connection conn;
    std::vector<std::string> message_parts;
};
