PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "users" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "username" TEXT NOT NULL UNIQUE,
    "email" TEXT NOT NULL UNIQUE,
    "password_hash" TEXT NOT NULL,
    "password_salt" TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS "channels" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL UNIQUE,
    "owner_id" INTEGER NOT NULL,
    "max_users" INTEGER NOT NULL
);
INSERT INTO users (id, username, email, password) VALUES (NULL, 'admin', 'admin@whisp.dev', 'password123');
INSERT INTO channels (id, name, owner_id, max_users) VALUES (NULL, 'general', 0, 256);
DELETE FROM sqlite_sequence;
COMMIT;
