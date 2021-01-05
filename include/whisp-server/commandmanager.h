#pragma once

#include "whisp-server/command.h"
#include "whisp-server/connection.h"
#include "whisp-server/messagemanager.h"

class CommandManager {
public:
  CommandManager(MessageManager *_message_manager,
                 std::unordered_set<Connection *, ConnectionHash> &_connections,
                 std::map<std::string, Channel *> &_channels)
      : message_manager(_message_manager), connections(_connections),
        channels(_channels) {}

  bool parse_command(Connection *conn, Command cmd);
  void join_channel_command(Connection *conn, std::vector<std::string> args);

private:
  bool login_command(Connection *conn, std::vector<std::string> args);
  bool register_command(Connection *conn, std::vector<std::string> args);
  bool set_command(Connection *conn, std::vector<std::string> args);
  void users_command(Connection *conn);
  void create_channel_command(Connection *conn, std::vector<std::string> args);

  MessageManager *message_manager;
  std::unordered_set<Connection *, ConnectionHash> &connections;
  std::map<std::string, Channel *> &channels;
};
