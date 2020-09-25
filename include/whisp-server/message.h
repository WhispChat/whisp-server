#pragma once

#include "whisp-server/connection.h"

#include <vector>

enum Command { Set, CloseConnection, Unknown };

class Message {
  public:
    Message(Connection conn, char *message);

    std::string get_fmt_str();
    Command get_command();
    std::vector<std::string> get_command_args();

    bool is_command = false;

  private:
    void split_message_parts();

    std::string message;
    Connection conn;
    std::vector<std::string> message_parts;
};
