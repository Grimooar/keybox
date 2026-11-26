CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, body TEXT NOT NULL, rev INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth (uid TEXT PRIMARY KEY, hash TEXT NOT NULL, fails INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS invites (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL, uses_left INTEGER NOT NULL, created_by TEXT NOT NULL);
-- Счётчики неудачных входов: по участнику и по паре «участник + адрес»
CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, fails INTEGER NOT NULL, locked_until INTEGER NOT NULL, window_start INTEGER NOT NULL);

-- Одноразовая отправка секрета: только шифртекст, ключ - во фрагменте ссылки у получателя
CREATE TABLE IF NOT EXISTS sends (id TEXT PRIMARY KEY, body TEXT NOT NULL, created_by TEXT NOT NULL, expires_at INTEGER NOT NULL, views_left INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS sends_expires ON sends (expires_at);

-- Журнал запросов: кто (uid), что (метод, класс пути, объект - cid или uid файла), когда, чем кончилось.
-- Без тел запросов, заголовков и параметров; адрес - только HMAC с секретом AUDIT_SALT (без него - '').
-- Строки - только проверенным участникам (подпись, пароль, принятая заявка); квота, потолок и срок - в handler.js.
-- ip NOT NULL DEFAULT '': сервер всегда пишет строку (''), так вставка проходит и на таблице первой версии
-- (ip TEXT NOT NULL), и на промежуточной (ip TEXT) - IF NOT EXISTS уже созданную таблицу не меняет.
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, uid TEXT, method TEXT NOT NULL, route TEXT NOT NULL, target TEXT, status INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
CREATE INDEX IF NOT EXISTS audit_uid ON audit (uid, id);
-- Квота журнала на участника: запросов за текущие сутки (day - номер дня с 1970) - чтений n_day и записей/удалений
-- w_day (у записей свой, более высокий потолок), и записанных строк всего n_all (для редкой чистки потолка)
CREATE TABLE IF NOT EXISTS audit_count (uid TEXT PRIMARY KEY, day INTEGER NOT NULL, n_day INTEGER NOT NULL, w_day INTEGER NOT NULL DEFAULT 0, n_all INTEGER NOT NULL);
-- Погашенные uid: удалённый участник или отклонённая заявка. uid задаёт сам заявитель, поэтому занять его
-- повторно нельзя никогда - иначе новый держатель приглашения получит чужие строки журнала, квоту и счётчики
CREATE TABLE IF NOT EXISTS retired_uids (uid TEXT PRIMARY KEY, at INTEGER NOT NULL);
-- Запросы без строки (без проверенного участника, неизвестный путь, сверх квоты - quota:<uid>:<путь>, сбой записи -
-- audit-error:<путь>) - счётчик: день (с 1970), класс пути, код ответа
CREATE TABLE IF NOT EXISTS audit_denied (day INTEGER NOT NULL, route TEXT NOT NULL, status INTEGER NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, route, status));
