#pragma once

#include "whisp-protobuf/cpp/client.pb.h"
#include <string>

class User {
public:
  unsigned int userID;
  std::string username;

  virtual void set_message_data(client::Message &user_msg) = 0;
  virtual std::string display_name() = 0;

  void set_username(std::string new_username) { this->username = new_username; }
};

class RegisteredUser : public User {
public:
  RegisteredUser(std::string new_username, std::string new_email,
                 std::string new_password);
  void set_message_data(client::Message &user_msg) override;
  std::string display_name() override;
  bool check_password(std::string password);

  std::string email;

private:
  std::string hashed_password;
};

class GuestUser : public User {
public:
  GuestUser(std::string new_username);
  void set_message_data(client::Message &user_msg) override;
  std::string display_name() override;
};
