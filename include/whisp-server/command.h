#pragma once

#include "whisp-server/connection.h"
#include "whisp-server/messagemanager.h"

#include <string>
#include <vector>

class Command {
public:
  Command(std::string message, MessageManager *_message_manager,
          std::unordered_set<Connection *, ConnectionHash> &_connections,
          std::map<std::string, Channel *> &_channels);

  static bool is_command(std::string message);

  bool parse_command(Connection *conn);
  void join_channel_command(Connection *conn);

private:
  std::vector<std::string> split_message_parts();

  void login_command(Connection *conn);
  void register_command(Connection *conn);
  void set_command(Connection *conn);
  void users_command(Connection *conn);
  void channels_command(Connection *conn);
  void create_channel_command(Connection *conn);

  std::string message;
  std::string type;
  std::vector<std::string> args;

  MessageManager *message_manager;
  std::unordered_set<Connection *, ConnectionHash> &connections;
  std::map<std::string, Channel *> &channels;
};
