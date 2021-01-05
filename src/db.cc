#include "whisp-server/db.h"
#include "whisp-server/logging.h"

namespace db {
sqlite3 *conn;
std::mutex user_read_last_id_mutex;

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

  user_read_last_id_mutex.lock();
  int rc = sqlite3_step(st);
  sqlite3_finalize(st);

  if (rc == SQLITE_CONSTRAINT) {
    user_read_last_id_mutex.unlock();
    throw std::runtime_error("Username/e-mail is already taken.");
  }

  if (rc == SQLITE_DONE) {
    int user_id = (int)sqlite3_last_insert_rowid(conn);
    user_read_last_id_mutex.unlock();
    return new RegisteredUser(user_id, username, email, password_hash,
                              password_salt);
  } else {
    user_read_last_id_mutex.unlock();
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
    int id = sqlite3_column_int(st, 0);
    std::string username = std::string((char *)sqlite3_column_text(st, 1));
    std::string email = std::string((char *)sqlite3_column_text(st, 2));
    std::string password_hash = std::string((char *)sqlite3_column_text(st, 3));
    std::string password_salt = std::string((char *)sqlite3_column_text(st, 4));
    sqlite3_finalize(st);

    return new RegisteredUser(id, username, email, password_hash,
                              password_salt);
  } else {
    sqlite3_finalize(st);
    LOG_ERROR << "Failed to get user: SQLite error " << rc << '\n';
    return nullptr;
  }
}

Channel *channel::add(std::string name, int owner_id, int max_users) {
  std::string sql = "INSERT INTO channels (id, name, owner_id, max_users) "
                    "VALUES (NULL, ?, ?, ?);";
  sqlite3_stmt *st;

  sqlite3_prepare_v2(conn, sql.c_str(), -1, &st, nullptr);
  sqlite3_bind_text(st, 1, name.c_str(), name.length(), SQLITE_TRANSIENT);
  sqlite3_bind_int(st, 2, owner_id);
  sqlite3_bind_int(st, 3, max_users);

  int rc = sqlite3_step(st);
  sqlite3_finalize(st);

  if (rc == SQLITE_CONSTRAINT) {
    throw std::runtime_error("Channel name is already in use.");
  }

  if (rc == SQLITE_DONE) {
    return new Channel(name, owner_id, max_users);
  } else {
    LOG_ERROR << "Failed to create channel: SQLite error " << rc << '\n';
    return nullptr;
  }
}

Channel *channel::get(std::string name) {
  std::string sql = "SELECT * FROM channels WHERE name = ?;";
  sqlite3_stmt *st;

  sqlite3_prepare_v2(conn, sql.c_str(), -1, &st, nullptr);
  sqlite3_bind_text(st, 1, name.c_str(), name.length(), SQLITE_TRANSIENT);

  int rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    std::string name = std::string((char *)sqlite3_column_text(st, 1));
    int owner_id = sqlite3_column_int(st, 2);
    int max_users = sqlite3_column_int(st, 3);
    sqlite3_finalize(st);

    return new Channel(name, owner_id, max_users);
  } else {
    sqlite3_finalize(st);
    LOG_ERROR << "Failed to get channel: SQLite error " << rc << '\n';
    return nullptr;
  }
}
} // namespace db
