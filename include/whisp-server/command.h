#pragma once

#include "whisp-server/connection.h"
#include "whisp-server/messagemanager.h"

#include <functional>
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
  void initialize_commands();
  std::vector<std::string> split_message_parts();

  void help_command(Connection *conn);
  void login_command(Connection *conn);
  void register_command(Connection *conn);
  void set_command(Connection *conn);
  void users_command(Connection *conn);
  void channels_command(Connection *conn);
  void create_command(Connection *conn);
  void private_message_command(Connection *conn);

  std::string message;
  std::string type;
  std::vector<std::string> args;
  std::vector<
      std::tuple<std::string, std::string, std::function<void(Connection *)>>>
      commands;
  MessageManager *message_manager;
  std::unordered_set<Connection *, ConnectionHash> &connections;
  std::map<std::string, Channel *> &channels;
};
