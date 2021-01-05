#include "whisp-server/user.h"
#include "whisp-server/hashing.h"

RegisteredUser::RegisteredUser(unsigned int new_user_id,
                               std::string new_username, std::string new_email,
                               std::string new_password_hash,
                               std::string new_password_salt) {
  user_id = new_user_id;
  username = new_username;
  email = new_email;
  password_hash = new_password_hash;
  password_salt = new_password_salt;
}

void RegisteredUser::set_message_data(client::Message &user_msg) {
  user::RegisteredUser *ru = new user::RegisteredUser();
  ru->set_username(username);
  ru->set_email(email);
  user_msg.set_allocated_registered_user(ru);
}

std::string RegisteredUser::display_name() { return username; }
bool RegisteredUser::is_registered() { return true; }

bool RegisteredUser::compare_hash(std::string password) {
  std::string new_hash = hashing::hash_password(password, this->password_salt);
  return password_hash.compare(new_hash) == 0;
}

GuestUser::GuestUser(std::string new_username) {
  user_id = 0;
  username = new_username;
}

void GuestUser::set_message_data(client::Message &user_msg) {
  user::GuestUser *gu = new user::GuestUser();
  gu->set_username(username);
  user_msg.set_allocated_guest_user(gu);
}

std::string GuestUser::display_name() { return username + " (guest)"; }
bool GuestUser::is_registered() { return false; }

UserBuilder *UserBuilder::set_registered() {
  this->registered = true;
  return this;
}

UserBuilder *UserBuilder::set_user_id(unsigned int user_id) {
  this->user_id = user_id;
  return this;
}

UserBuilder *UserBuilder::set_username(std::string username) {
  this->username = username;
  return this;
}

UserBuilder *UserBuilder::set_email(std::string email) {
  this->email = email;
  return this;
}

UserBuilder *UserBuilder::set_password_hash(std::string password_hash) {
  this->password_hash = password_hash;
  return this;
}

UserBuilder *UserBuilder::set_password_salt(std::string password_salt) {
  this->password_salt = password_salt;
  return this;
}

User *UserBuilder::build() {
  if (registered) {
    return new RegisteredUser(user_id, username, email, password_hash,
                              password_salt);
  }

  return new GuestUser(username);
}