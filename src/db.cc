#include "whisp-server/db.h"
#include "whisp-server/logging.h"

namespace db {
sqlite3 *conn;

void init_database(std::string sqlite_path) {
  if (sqlite3_open_v2(sqlite_path.c_str(), &conn, SQLITE_OPEN_READWRITE,
                      nullptr)) {
    throw std::string("Can't open database: " +
                      std::string(sqlite3_errmsg(conn)));
  }
}

void close_database() {
  if (conn) {
    sqlite3_close(conn);
  }
}

RegisteredUser *user::add(std::string username, std::string email,
                          std::string password_hash,
                          std::string password_salt) {
  std::string sql =
      "INSERT INTO users (id,username,email,password_hash,password_salt) "
      "VALUES (NULL,?,?,?,?)";
  sqlite3_stmt *st;

  sqlite3_prepare_v2(conn, sql.c_str(), -1, &st, nullptr);
  sqlite3_bind_text(st, 1, username.c_str(), username.length(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, email.c_str(), email.length(), SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, password_hash.c_str(), password_hash.length(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 4, password_salt.c_str(), password_salt.length(),
                    SQLITE_TRANSIENT);

  int rc = sqlite3_step(st);
  sqlite3_finalize(st);

  if (rc == SQLITE_CONSTRAINT) {
    throw "Username already exists.";
  }

  if (rc == SQLITE_DONE) {
    return new RegisteredUser(username, email, password_hash, password_salt);
  } else {
    LOG_ERROR << "Failed to register user: SQLite error " << rc << '\n';
    return nullptr;
  }
}

RegisteredUser *user::get(std::string username) {
  std::string sql = "SELECT * FROM users WHERE username=?";
  sqlite3_stmt *st;

  sqlite3_prepare_v2(conn, sql.c_str(), -1, &st, nullptr);
  sqlite3_bind_text(st, 1, username.c_str(), username.length(),
                    SQLITE_TRANSIENT);

  int rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    std::string username = std::string((char *)sqlite3_column_text(st, 1));
    std::string email = std::string((char *)sqlite3_column_text(st, 2));
    std::string password_hash = std::string((char *)sqlite3_column_text(st, 3));
    std::string password_salt = std::string((char *)sqlite3_column_text(st, 4));
    sqlite3_finalize(st);

    return new RegisteredUser(username, email, password_hash, password_salt);
  } else {
    sqlite3_finalize(st);
    LOG_ERROR << "Failed to get user: SQLite error " << rc << '\n';
    return nullptr;
  }
}
} // namespace db
