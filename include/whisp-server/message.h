#pragma once

#include "whisp-server/command.h"
#include "whisp-server/connection.h"

#include <vector>

class Message {
  public:
    Message(Connection conn, std::string message);

    std::string get_fmt_str();
    Command get_command();

    std::string message;
    bool is_command = false;

  private:
    void split_message_parts();

    Connection conn;
    std::vector<std::string> message_parts;
};
