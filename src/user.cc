#include "whisp-server/user.h"

RegisteredUser::RegisteredUser(std::string new_username, std::string new_email,
                               std::string new_password) {
  userID = 0;
  username = new_username;
  email = new_email;
  // TODO: Obviously not final, password auth/encryption is considered for later
  hashed_password = "hashed_" + new_password;
}

void RegisteredUser::set_message_data(client::Message &user_msg) {
  user::RegisteredUser *ru = new user::RegisteredUser();
  ru->set_username(username);
  ru->set_email(email);
  user_msg.set_allocated_registered_user(ru);
}

bool RegisteredUser::check_password(std::string password) {
  // TODO: compare actual hash
  return hashed_password.compare("hashed_" + password) == 0;
}

GuestUser::GuestUser(std::string new_username) {
  userID = 0;
  username = new_username;
}

void GuestUser::set_message_data(client::Message &user_msg) {
  user::GuestUser *gu = new user::GuestUser();
  gu->set_username(username);
  user_msg.set_allocated_guest_user(gu);
}
