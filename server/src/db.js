// Хранилище сервера. put(path, body, rev) - запись «если версия не изменилась»:
// rev = null - только создать; возвращает новую версию или null при конфликте.

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
  constructor() { this.files = new Map(); this.m = new Map(); this.auth = new Map(); this.invites = new Map(); this.attempts = new Map(); this.sends = new Map(); }
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
