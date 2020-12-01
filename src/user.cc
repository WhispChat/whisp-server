#include "whisp-server/user.h"

RegisteredUser::RegisteredUser(std::string new_username, std::string new_email,
                               std::string new_password_hash) {
  userID = 0;
  username = new_username;
  email = new_email;
  password_hash = new_password_hash;
}

void RegisteredUser::set_message_data(client::Message &user_msg) {
  user::RegisteredUser *ru = new user::RegisteredUser();
  ru->set_username(username);
  ru->set_email(email);
  user_msg.set_allocated_registered_user(ru);
}

std::string RegisteredUser::display_name() { return username; }

bool RegisteredUser::compare_hash(std::string given_hash) {
  return password_hash.compare(given_hash) == 0;
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

std::string GuestUser::display_name() { return username + " (guest)"; }
