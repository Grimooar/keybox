// Хранилище сервера. put(path, body, rev) - запись «если версия не изменилась»:
// rev = null - только создать; возвращает новую версию или null при конфликте.

const DAY = 24 * 3600 * 1000;
const AUDIT_TRIM_EVERY = 256; // потолок строк участника проверяется раз в столько его строк

export class D1Store {
  constructor(d1) { this.d1 = d1; }

  async get(path) {
    return this.d1.prepare('SELECT body, rev FROM files WHERE path = ?').bind(path).first();
  }

  async put(path, body, rev) {
    if (rev == null) {
      const r = await this.d1.prepare('INSERT INTO files (path, body, rev) VALUES (?, ?, 1) ON CONFLICT(path) DO NOTHING').bind(path, body).run();
      return r.meta.changes ? 1 : null;
    }
    const r = await this.d1.prepare('UPDATE files SET body = ?, rev = rev + 1 WHERE path = ? AND rev = ?').bind(body, path, rev).run();
    return r.meta.changes ? rev + 1 : null;
  }

  async del(path) { await this.d1.prepare('DELETE FROM files WHERE path = ?').bind(path).run(); }

  async list(prefix) {
    const { results } = await this.d1.prepare('SELECT path FROM files WHERE substr(path, 1, ?) = ? ORDER BY path').bind(prefix.length, prefix).all();
    return results.map(r => r.path);
  }

  async meta(key) {
    return (await this.d1.prepare('SELECT value FROM meta WHERE key = ?').bind(key).first())?.value ?? null;
  }

  async metaInit(key, value) {
    const r = await this.d1.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING').bind(key, value).run();
    return !!r.meta.changes;
  }

  async setMeta(key, value) {
    await this.d1.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(key, value).run();
  }

  async getAuth(uid) { return this.d1.prepare('SELECT hash, fails, locked_until FROM auth WHERE uid = ?').bind(uid).first(); }

  async setAuth(uid, hash) {
    await this.d1.prepare('INSERT INTO auth (uid, hash, fails, locked_until) VALUES (?, ?, 0, 0) ON CONFLICT(uid) DO UPDATE SET hash = excluded.hash, fails = 0, locked_until = 0').bind(uid, hash).run();
  }


  async delAuth(uid) { await this.d1.prepare('DELETE FROM auth WHERE uid = ?').bind(uid).run(); }

  async addInvite(hash, expires, uses, by) {
    await this.d1.prepare('INSERT INTO invites (hash, expires, uses_left, created_by) VALUES (?, ?, ?, ?)').bind(hash, expires, uses, by).run();
  }

  // Одним запросом: гонка из параллельных заявок не превысит лимит
  async useInvite(hash, now) {
    const r = await this.d1.prepare('UPDATE invites SET uses_left = uses_left - 1 WHERE hash = ? AND uses_left > 0 AND expires > ?').bind(hash, now).run();
    await this.d1.prepare('DELETE FROM invites WHERE expires < ? OR uses_left <= 0').bind(now).run();
    return r.meta.changes === 1;
  }

  // Засчитать попытку входа (атомарно) и вернуть, сколько их было в текущем окне
  async attempt(key, now, windowMs) {
    return this.d1.prepare(`INSERT INTO attempts (key, fails, locked_until, window_start) VALUES (?1, 1, 0, ?2)
      ON CONFLICT(key) DO UPDATE SET
        fails = CASE WHEN window_start <= ?2 - ?3 THEN 1 ELSE fails + 1 END,
        window_start = CASE WHEN window_start <= ?2 - ?3 THEN ?2 ELSE window_start END
      RETURNING fails, window_start`).bind(key, now, windowMs).first();
  }

  // Есть ли запись не старше windowMs (без увеличения счётчика)
  async peekAttempt(key, now, windowMs) {
    return !!await this.d1.prepare('SELECT 1 FROM attempts WHERE key = ? AND window_start > ?').bind(key, now - windowMs).first();
  }
  async forgive(key) { await this.d1.prepare('UPDATE attempts SET fails = MAX(fails - 1, 0) WHERE key = ?').bind(key).run(); }
  async clearAttempts(key) { await this.d1.prepare('DELETE FROM attempts WHERE key = ?').bind(key).run(); }

  // ---------- одноразовые ссылки (sends) ----------
  async addSend(id, body, by, expires, views, now) {
    await this.d1.batch([
      this.d1.prepare('DELETE FROM sends WHERE expires_at <= ? OR views_left <= 0').bind(now),
      this.d1.prepare('INSERT INTO sends (id, body, created_by, expires_at, views_left) VALUES (?, ?, ?, ?, ?)').bind(id, body, by, expires, views),
    ]);
  }
  // Атомарно списать просмотр; последняя/просроченная запись удаляется
  async takeSend(id, now) {
    const r = await this.d1.prepare('UPDATE sends SET views_left = views_left - 1 WHERE id = ? AND views_left > 0 AND expires_at > ? RETURNING body, views_left').bind(id, now).first();
    await this.d1.prepare('DELETE FROM sends WHERE expires_at <= ? OR views_left <= 0').bind(now).run();
    return r || null;
  }
  async getSend(id) { return this.d1.prepare('SELECT id, created_by, expires_at, views_left FROM sends WHERE id = ?').bind(id).first(); }
  async delSend(id) { await this.d1.prepare('DELETE FROM sends WHERE id = ?').bind(id).run(); }

  // ---------- журнал запросов ----------
  // Строка проверенного участника. Квота и потолок - на uid: счётчик в audit_count (строка на участника),
  // сверх perDay за сутки - одна строка audit-quota и дальше ничего ('quota'); чистка: старше срока (по индексу ts)
  // и сверх keep строк этого же участника (по индексу uid, id) - раз в trimEvery его строк, чтобы не читать индекс каждый раз
  async addAudit(r, { before, perDay, keep, trimEvery = AUDIT_TRIM_EVERY }) {
    const c = await this.d1.prepare(`INSERT INTO audit_count (uid, day, n_day, n_all) VALUES (?1, ?2, 1, 1)
      ON CONFLICT (uid) DO UPDATE SET n_day = CASE WHEN day = ?2 THEN n_day + 1 ELSE 1 END, day = ?2, n_all = n_all + 1
      RETURNING n_day, n_all`).bind(r.uid, Math.floor(r.ts / DAY)).first();
    if (c.n_day > perDay + 1) return 'quota';
    const row = c.n_day > perDay ? { ...r, route: 'audit-quota', target: null } : r;
    const list = [
      this.d1.prepare('INSERT INTO audit (ts, uid, method, route, target, status, ip) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(row.ts, row.uid, row.method, row.route, row.target, row.status, row.ip),
      this.d1.prepare('DELETE FROM audit WHERE ts < ?').bind(before),
    ];
    if (c.n_all % trimEvery === 0) {
      list.push(this.d1.prepare('DELETE FROM audit WHERE uid = ?1 AND id <= (SELECT id FROM audit WHERE uid = ?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)').bind(r.uid, keep));
    }
    await this.d1.batch(list);
    return row === r ? 'row' : 'quota';
  }
  // Запросы без строки журнала - счётчик на (день, класс пути, код): таблица растёт не быстрее числа дней
  async countDenied({ day, route, status }, beforeDay) {
    await this.d1.batch([
      this.d1.prepare(`INSERT INTO audit_denied (day, route, status, n) VALUES (?, ?, ?, 1)
        ON CONFLICT (day, route, status) DO UPDATE SET n = n + 1`).bind(day, route, status),
      this.d1.prepare('DELETE FROM audit_denied WHERE day < ?').bind(beforeDay),
    ]);
  }
  async listDenied({ sinceDay }) {
    const { results } = await this.d1.prepare('SELECT day, route, status, n FROM audit_denied WHERE day >= ? ORDER BY day, route, status').bind(sinceDay).all();
    return results;
  }
  async listAudit({ uid, after, since, limit }) {
    const { results } = await this.d1.prepare(`SELECT id, ts, uid, method, route, target, status, ip FROM audit
      WHERE id > ?1 AND ts >= ?2 AND (?3 IS NULL OR uid = ?3) ORDER BY id LIMIT ?4`).bind(after, since, uid, limit).all();
    return results;
  }

  // Создание команды - всё или ничего (D1 batch выполняется одной транзакцией)
  async setupAll({ pin, teamHash, uid, userBody, authHash, orgBody }) {
    try {
      await this.d1.batch([
        this.d1.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').bind('pin', pin),
        this.d1.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').bind('team', teamHash),
        this.d1.prepare('INSERT INTO files (path, body, rev) VALUES (?, ?, 1)').bind('users/' + uid, userBody),
        this.d1.prepare('INSERT INTO auth (uid, hash) VALUES (?, ?)').bind(uid, authHash),
        this.d1.prepare('INSERT INTO files (path, body, rev) VALUES (?, ?, 1)').bind('org.json', orgBody),
      ]);
      return true;
    } catch {
      return false;
    }
  }
}

// То же самое в памяти - для тестов
export class MemoryStore {
  constructor() { this.files = new Map(); this.m = new Map(); this.auth = new Map(); this.invites = new Map(); this.attempts = new Map(); this.sends = new Map(); this.audit = []; this.auditId = 0; this.auditCount = new Map(); this.denied = new Map(); }
  async addAudit(r, { before, perDay, keep, trimEvery = AUDIT_TRIM_EVERY }) {
    const day = Math.floor(r.ts / DAY);
    const c = this.auditCount.get(r.uid) || { day, n_day: 0, n_all: 0 };
    c.n_day = c.day === day ? c.n_day + 1 : 1; c.day = day; c.n_all++;
    this.auditCount.set(r.uid, c);
    if (c.n_day > perDay + 1) return 'quota';
    const row = c.n_day > perDay ? { ...r, route: 'audit-quota', target: null } : r;
    this.audit.push({ id: ++this.auditId, ...row });
    this.audit = this.audit.filter(a => a.ts >= before);
    if (c.n_all % trimEvery === 0) {
      const own = this.audit.filter(a => a.uid === r.uid);
      if (own.length > keep) { const cut = own.at(-keep - 1).id; this.audit = this.audit.filter(a => a.uid !== r.uid || a.id > cut); }
    }
    return row === r ? 'row' : 'quota';
  }
  async countDenied({ day, route, status }, beforeDay) {
    const k = JSON.stringify([day, route, status]);
    this.denied.set(k, (this.denied.get(k) || 0) + 1);
    for (const key of this.denied.keys()) if (JSON.parse(key)[0] < beforeDay) this.denied.delete(key);
  }
  async listDenied({ sinceDay }) {
    return [...this.denied].map(([k, n]) => { const [day, route, status] = JSON.parse(k); return { day, route, status, n }; })
      .filter(r => r.day >= sinceDay).sort((a, b) => a.day - b.day || a.route.localeCompare(b.route) || a.status - b.status);
  }
  async listAudit({ uid, after, since, limit }) {
    return this.audit.filter(a => a.id > after && a.ts >= since && (uid == null || a.uid === uid)).slice(0, limit).map(a => ({ ...a }));
  }
  async get(path) { const f = this.files.get(path); return f ? { ...f } : null; }
  async put(path, body, rev) {
    const f = this.files.get(path);
    if (rev == null ? f : !f || f.rev !== rev) return null;
    const nr = f ? f.rev + 1 : 1;
    this.files.set(path, { body, rev: nr });
    return nr;
  }
  async del(path) { this.files.delete(path); }
  async list(prefix) { return [...this.files.keys()].filter(p => p.startsWith(prefix)).sort(); }
  async meta(k) { return this.m.get(k) ?? null; }
  async metaInit(k, v) { if (this.m.has(k)) return false; this.m.set(k, v); return true; }
  async setMeta(k, v) { this.m.set(k, v); }
  async getAuth(uid) { const a = this.auth.get(uid); return a ? { ...a } : null; }
  async setAuth(uid, hash) { this.auth.set(uid, { hash, fails: 0, locked_until: 0 }); }
  async delAuth(uid) { this.auth.delete(uid); }
  async addInvite(hash, expires, uses) { this.invites.set(hash, { hash, expires, uses_left: uses }); }
  async useInvite(hash, now) {
    const i = this.invites.get(hash);
    if (!i || i.uses_left <= 0 || i.expires <= now) return false;
    i.uses_left--;
    return true;
  }
  async attempt(key, now, windowMs) {
    const a = this.attempts.get(key);
    if (!a || a.window_start <= now - windowMs) this.attempts.set(key, { fails: 1, window_start: now });
    else a.fails++;
    return { ...this.attempts.get(key) };
  }
  async peekAttempt(key, now, windowMs) { const a = this.attempts.get(key); return !!a && a.window_start > now - windowMs; }
  async forgive(key) { const a = this.attempts.get(key); if (a) a.fails = Math.max(a.fails - 1, 0); }
  async clearAttempts(key) { this.attempts.delete(key); }
  async setupAll({ pin, teamHash, uid, userBody, authHash, orgBody }) {
    if (this.m.has('pin')) return false;
    this.m.set('pin', pin);
    this.m.set('team', teamHash);
    this.files.set('users/' + uid, { body: userBody, rev: 1 });
    this.auth.set(uid, { hash: authHash });
    this.files.set('org.json', { body: orgBody, rev: 1 });
    return true;
  }

  sweepSends(now) { for (const [k, v] of this.sends) if (v.expires_at <= now || v.views_left <= 0) this.sends.delete(k); }
  async addSend(id, body, by, expires, views, now) { this.sweepSends(now); this.sends.set(id, { id, body, created_by: by, expires_at: expires, views_left: views }); }
  async takeSend(id, now) {
    const s = this.sends.get(id);
    const ok = s && s.views_left > 0 && s.expires_at > now;
    if (ok) s.views_left--;
    const out = ok ? { body: s.body, views_left: s.views_left } : null;
    this.sweepSends(now);
    return out;
  }
  async getSend(id) { const s = this.sends.get(id); return s ? { ...s } : null; }
  async delSend(id) { this.sends.delete(id); }
}
