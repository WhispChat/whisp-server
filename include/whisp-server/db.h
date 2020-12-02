#pragma once

#include "whisp-server/user.h"
#include "whisp-server/channel.h"

#include <sqlite3.h>
#include <string>

namespace db {
  extern sqlite3 *conn;

  void init_database(std::string sqlite_path);
  void close_database();

  namespace user {
    RegisteredUser *add(std::string username, std::string email,
                        std::string password_hash, std::string password_salt);
    RegisteredUser *get(std::string username);
  } // namespace user

  namespace channel {
    Channel *add(std::string name, int owner_id, int max_users);
    Channel *get(std::string name);
  }
} // namespace db