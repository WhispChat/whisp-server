#pragma once

#include "whisp-protobuf/cpp/client.pb.h"
#include <string>

class User {
public:
  std::string username;

  virtual void set_message_data(client::Message &user_msg) = 0;
  virtual std::string display_name() = 0;

  void set_username(std::string new_username) { this->username = new_username; }

  bool operator==(const User &u) const { return this->userID == u.userID; }

protected:
  unsigned int userID;
};

class RegisteredUser : public User {
public:
  RegisteredUser(unsigned int new_userID, std::string new_username,
                 std::string new_email, std::string new_password_hash,
                 std::string new_password_salt);
  void set_message_data(client::Message &user_msg) override;
  std::string display_name() override;
  bool compare_hash(std::string password);

  std::string email;

private:
  std::string password_hash;
  std::string password_salt;
};

class GuestUser : public User {
public:
  GuestUser(std::string new_username);
  void set_message_data(client::Message &user_msg) override;
  std::string display_name() override;
};
