#pragma once

#include "whisp-protobuf/cpp/client.pb.h"
#include <string>

class User {
public:
  std::string username;

  virtual void set_message_data(client::Message &user_msg) = 0;

  void set_username(std::string new_username) { this->username = new_username; }

protected:
  unsigned int userID;
};

class RegisteredUser : public User {
public:
  RegisteredUser(std::string new_username, std::string new_email,
                 std::string new_password);
  void set_message_data(client::Message &user_msg) override;
  bool check_password(std::string password);

  std::string email;

private:
  std::string hashed_password;
};

class GuestUser : public User {
public:
  GuestUser(std::string new_username);
  void set_message_data(client::Message &user_msg) override;
};
