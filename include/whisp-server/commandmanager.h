#pragma once

#include "whisp-server/command.h"
#include "whisp-server/connection.h"
#include "whisp-server/messagemanager.h"

class CommandManager {
public:
  CommandManager(MessageManager *_message_manager,
                 std::unordered_set<Connection *, ConnectionHash> &_connections)
      : message_manager(_message_manager), connections(_connections) {}

  bool parse_command(Connection *conn, Command cmd);

private:
  void send_and_create(server::Message::MessageType type, std::string content,
                       Connection *conn);

  bool login_command(Connection *conn, std::vector<std::string> args);
  bool register_command(Connection *conn, std::vector<std::string> args);
  bool set_command(Connection *conn, std::vector<std::string> args);
  void users_command(Connection *conn);

  MessageManager *message_manager;
  std::unordered_set<Connection *, ConnectionHash> &connections;
};
