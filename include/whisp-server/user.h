#pragma once

#include <string>

class User {
public:
  std::string username;

  void set_username(std::string new_username);

protected:
  unsigned int userID;
};

class RegisteredUser : public User {
public:
  RegisteredUser(std::string new_username, std::string new_email,
                 std::string new_password);

private:
  std::string email;
  std::string hashed_password;
};

class GuestUser : public User {
public:
  GuestUser(std::string new_username);
};
