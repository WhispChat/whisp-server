#pragma once

#include "whisp-server/user.h"

#include <sqlite3.h>
#include <string>

namespace db {
extern sqlite3 *conn;

void init_database(std::string sqlite_path);
void close_database();

namespace user {
RegisteredUser *add(std::string username, std::string email,
                    std::string password);
RegisteredUser *get(std::string username);
}
}