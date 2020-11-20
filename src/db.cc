#include "whisp-server/db.h"

namespace db {
sqlite3 *conn;

void init_database(std::string sqlite_path) {
  if (sqlite3_open(sqlite_path.c_str(), &conn)) {
    throw "Can't open database: " + std::string(sqlite3_errmsg(conn));
  }
}

void close_database() {
  if (conn) {
    sqlite3_close(conn);
  }
}

RegisteredUser *user::add(std::string username, std::string email,
                          std::string password) {
  std::string sql =
      "INSERT INTO users (id,username,email,password) VALUES (NULL,?,?,?)";
  sqlite3_stmt *st;

  sqlite3_prepare_v2(conn, sql.c_str(), -1, &st, nullptr);
  sqlite3_bind_text(st, 1, username.c_str(), username.length(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, email.c_str(), email.length(), SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, password.c_str(), password.length(),
                    SQLITE_TRANSIENT);

  // TODO: check if username exists before inserting
  int rc = sqlite3_step(st);
  sqlite3_finalize(st);

  if (rc == SQLITE_DONE) {
    return new RegisteredUser(username, email, password);
  } else {
    return nullptr;
  }
}

RegisteredUser *user::get(std::string username) {
  std::string sql = "SELECT * FROM users WHERE username=?";
  sqlite3_stmt *st;

  sqlite3_prepare_v2(conn, sql.c_str(), -1, &st, nullptr);
  sqlite3_bind_text(st, 1, username.c_str(), username.length(),
                    SQLITE_TRANSIENT);

  if (sqlite3_step(st) == SQLITE_ROW) {
    std::string username = std::string((char *)sqlite3_column_text(st, 1));
    std::string email = std::string((char *)sqlite3_column_text(st, 2));
    std::string password = std::string((char *)sqlite3_column_text(st, 3));
    sqlite3_finalize(st);

    return new RegisteredUser(username, email, password);
  } else {
    sqlite3_finalize(st);
    return nullptr;
  }
}
}
