CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, body TEXT NOT NULL, rev INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth (uid TEXT PRIMARY KEY, hash TEXT NOT NULL, fails INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS invites (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL, uses_left INTEGER NOT NULL, created_by TEXT NOT NULL);
-- Счётчики неудачных входов: по участнику и по паре «участник + адрес»
CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, fails INTEGER NOT NULL, locked_until INTEGER NOT NULL, window_start INTEGER NOT NULL);

-- Одноразовая отправка секрета: только шифртекст, ключ - во фрагменте ссылки у получателя
CREATE TABLE IF NOT EXISTS sends (id TEXT PRIMARY KEY, body TEXT NOT NULL, created_by TEXT NOT NULL, expires_at INTEGER NOT NULL, views_left INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS sends_expires ON sends (expires_at);
