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

  async setFails(uid, fails, lockedUntil) {
    await this.d1.prepare('UPDATE auth SET fails = ?, locked_until = ? WHERE uid = ?').bind(fails, lockedUntil, uid).run();
  }

  async delAuth(uid) { await this.d1.prepare('DELETE FROM auth WHERE uid = ?').bind(uid).run(); }

  async addInvite(hash, expires, uses, by) {
    await this.d1.prepare('INSERT INTO invites (hash, expires, uses_left, created_by) VALUES (?, ?, ?, ?)').bind(hash, expires, uses, by).run();
  }

  async getInvite(hash) { return this.d1.prepare('SELECT hash, expires, uses_left FROM invites WHERE hash = ?').bind(hash).first(); }

  async useInvite(hash) {
    await this.d1.prepare('UPDATE invites SET uses_left = uses_left - 1 WHERE hash = ?').bind(hash).run();
    await this.d1.prepare('DELETE FROM invites WHERE expires < ? OR uses_left <= 0').bind(Date.now()).run();
  }
}

// То же самое в памяти - для тестов
export class MemoryStore {
  constructor() { this.files = new Map(); this.m = new Map(); this.auth = new Map(); this.invites = new Map(); }
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
  async setFails(uid, fails, lockedUntil) { const a = this.auth.get(uid); if (a) Object.assign(a, { fails, locked_until: lockedUntil }); }
  async delAuth(uid) { this.auth.delete(uid); }
  async addInvite(hash, expires, uses) { this.invites.set(hash, { hash, expires, uses_left: uses }); }
  async getInvite(hash) { const i = this.invites.get(hash); return i ? { ...i } : null; }
  async useInvite(hash) { const i = this.invites.get(hash); if (i) i.uses_left--; }
}
