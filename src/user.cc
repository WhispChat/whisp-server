#include "whisp-server/user.h"

void User::set_username(std::string new_username) {
  this->username = new_username;
}

RegisteredUser::RegisteredUser(std::string new_username, std::string new_email,
                               std::string new_password) {
  userID = 0;
  username = new_username;
  email = new_email;
  // TODO: Obviously not final, password auth/encryption is considered for later
  hashed_password = "hashed_" + new_password;
}

GuestUser::GuestUser(std::string new_username) {
  userID = 0;
  username = new_username;
}