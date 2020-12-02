#pragma once

#include "whisp-server/user.h"
#include "whisp-protobuf/cpp/client.pb.h"
#include <string>
#include <vector>

class Channel {
public:
  Channel(std::string name, int owner_id, int max_users);
  std::string name;
  int owner_id;
  int max_users;

  void add_user(std::string username);
  void remove_user(std::string username);
  std::string get_users_list();
  int get_connection_amount() { return connected_users.size(); };

private:
  std::vector<std::string> connected_users;
};

