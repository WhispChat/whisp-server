#include "whisp-server/channel.h"
#include "whisp-server/user.h"

Channel::Channel(std::string name, int owner_id, int max_users) {
  this->name = name;
  this->owner_id = owner_id;
  this->max_users = max_users;
}

void Channel::add_user(std::string username) {
  this->connected_users.push_back(username);
}

void Channel::remove_user(std::string username) {
  for (int i = 0; i < connected_users.size(); i++) {
    if (connected_users[i] == username) {
      connected_users.erase(connected_users.begin() + i);
      break;
    }
  }
}

std::string Channel::get_users_list() {
  std::string user_list;
  for (auto connected_user : connected_users) {
    user_list += connected_user + ", ";
  }
  return user_list.substr(0, user_list.size() - 2);
}