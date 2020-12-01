#pragma once

#include "whisp-protobuf/cpp/client.pb.h"
#include <string>

class User {
public:
  std::string username;

  virtual void set_message_data(client::Message &user_msg) = 0;
  virtual std::string display_name() = 0;

  void set_username(std::string new_username) { this->username = new_username; }

protected:
  unsigned int userID;
};

class RegisteredUser : public User {
public:
  RegisteredUser(std::string new_username, std::string new_email,
                 std::string new_password);
  void set_message_data(client::Message &user_msg) override;
  std::string display_name() override;
  bool compare_hash(std::string given_hash);

  std::string email;

private:
  std::string password_hash;
};

class GuestUser : public User {
public:
  GuestUser(std::string new_username);
  void set_message_data(client::Message &user_msg) override;
  std::string display_name() override;
};
