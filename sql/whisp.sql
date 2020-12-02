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
INSERT INTO users (id, username, email, password_hash, password_salt) VALUES (NULL, 'admin', 'admin@whisp.dev',
                                                                              'fad24daa6c774da1e47c0d0c0af525ad17a3821b4a528ce5047f2cdf4baae19',
                                                                              'c7d0111374bec5b5b42cf08a6a8a30ea8ca75314177bd7a04fd61221698a6277');
INSERT INTO channels (id, name, owner_id, max_users) VALUES (NULL, 'general', 0, 256);
DELETE FROM sqlite_sequence;
COMMIT;
