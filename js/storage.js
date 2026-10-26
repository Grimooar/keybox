// Хранилища файлов. У всех одинаковый интерфейс:
//   read(path)             -> { text, rev } | null
//   write(path, text, rev) -> newRev   (rev = null - только создать новый файл)
//   list(dir)              -> [имена файлов]
//   remove(path)
// Если файл изменили одновременно с другого устройства, write бросает ConflictError,
// и вызывающий код перечитывает файл и повторяет операцию.
// ApiStorage дополнительно умеет вход по паролю (prelogin/login) и подписывает запросы.

import { requestPayload, sha256b64, signObj } from './crypto.js';

export class ConflictError extends Error {}
export class NetworkError extends Error {}
export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export class MemoryStorage {
  constructor() { this.files = new Map(); this.n = 0; }

  async read(path) {
    const f = this.files.get(path.toLowerCase());
    return f ? { text: f.text, rev: f.rev } : null;
  }

  async write(path, text, rev) {
    const key = path.toLowerCase();
    const f = this.files.get(key);
    if (rev == null ? f : (!f || f.rev !== rev)) throw new ConflictError(path);
    const newRev = 'r' + (++this.n);
    this.files.set(key, { text, rev: newRev, name: path.split('/').pop() });
    return newRev;
  }

  async list(dir) {
    const prefix = dir.toLowerCase().replace(/\/$/, '') + '/';
    return [...this.files.entries()]
      .filter(([k]) => k.startsWith(prefix) && !k.slice(prefix.length).includes('/'))
      .map(([, f]) => f.name);
  }

  async remove(path) { this.files.delete(path.toLowerCase()); }
}

// Клиент сервера Ключницы (server/). team - секрет команды из ссылки.
export class ApiStorage {
  constructor(base, team, fetchFn = (...a) => globalThis.fetch(...a)) {
    this.base = base.replace(/\/+$/, '');
    this.team = team;
    this.fetch = fetchFn;
    this.id = null;     // { uid, signSk } после входа
    this.invite = null; // токен приглашения для заявки
  }

  authenticate(uid, signSk) { this.id = { uid, signSk }; }

  async req(method, path, body = null, { sign = true, headers = {} } = {}) {
    const h = { ...headers };
    if (this.team) h['X-KB-Team'] = this.team;
    if (body != null) h['Content-Type'] = 'text/plain;charset=utf-8';
    if (sign && this.id) {
      const ts = Date.now();
      const sig = await signObj(this.id.signSk, requestPayload(method, '/' + path, ts, await sha256b64(body ?? '')));
      h['X-KB-Auth'] = `${this.id.uid}:${ts}:${sig}`;
    }
    let r;
    try {
      r = await this.fetch(this.base + '/' + path, { method, headers: h, body: body ?? undefined });
    } catch (e) {
      throw new NetworkError('Нет связи с сервером');
    }
    const data = await r.json().catch(() => ({}));
    return { r, data };
  }

  static fail(r, data) {
    return new ApiError(r.status, data.error || 'Сервер ответил ' + r.status);
  }

  async status() {
    const { r, data } = await this.req('GET', 'api/status', null, { sign: false });
    if (!r.ok) throw ApiStorage.fail(r, data);
    return data;
  }

  async read(path) {
    const { r, data } = await this.req('GET', 'api/f/' + path);
    if (r.status === 404) return null;
    if (!r.ok) throw ApiStorage.fail(r, data);
    return { text: data.text, rev: Number(r.headers.get('X-KB-Rev')) };
  }

  async write(path, text, rev) {
    // Новый участник ещё без ключей на сервере: заявку пропускает токен приглашения
    const join = rev == null && path.startsWith('users/') && this.invite && !this.id;
    const { r, data } = await this.req('PUT', `api/f/${path}?rev=${rev == null ? 'new' : rev}`, text,
      join ? { sign: false, headers: { 'X-KB-Invite': this.invite } } : {});
    if (r.status === 409) throw new ConflictError(data.error || path);
    if (!r.ok) throw ApiStorage.fail(r, data);
    return Number(r.headers.get('X-KB-Rev'));
  }

  async list(dir) {
    const { r, data } = await this.req('GET', 'api/list/' + dir.replace(/\/+$/, ''));
    if (!r.ok) throw ApiStorage.fail(r, data);
    return data.names;
  }

  async remove(path) {
    const { r, data } = await this.req('DELETE', 'api/f/' + path);
    if (!r.ok && r.status !== 404) throw ApiStorage.fail(r, data);
  }

  async people() {
    const { r, data } = await this.req('GET', 'api/people', null, { sign: false });
    if (!r.ok) throw ApiStorage.fail(r, data);
    return data.people;
  }

  async prelogin(uid) {
    const { r, data } = await this.req('GET', 'api/prelogin/' + uid, null, { sign: false });
    if (!r.ok) throw ApiStorage.fail(r, data);
    return data;
  }

  async login(uid, authKey) {
    const { r, data } = await this.req('POST', 'api/login', JSON.stringify({ uid, authKey }), { sign: false });
    if (!r.ok) throw ApiStorage.fail(r, data);
    return { text: data.text, rev: Number(r.headers.get('X-KB-Rev')) };
  }

  async setup(payload) {
    const { r, data } = await this.req('POST', 'api/setup', JSON.stringify(payload), { sign: false });
    if (!r.ok) throw ApiStorage.fail(r, data);
  }

  async createInvite() {
    const { r, data } = await this.req('POST', 'api/invites', '');
    if (!r.ok) throw ApiStorage.fail(r, data);
    return data;
  }
}

// Обёртка: запоминает последние прочитанные (зашифрованные) ответы,
// чтобы без интернета можно было открыть сейф и смотреть пароли.
export class CachedStorage {
  constructor(inner, ns, store = globalThis.localStorage) {
    this.inner = inner;
    this.ns = 'kb.cache.' + ns + ':';
    this.store = store;
    this.offline = false;
  }

  get(key) {
    try { const v = this.store?.getItem(this.ns + key); return v == null ? undefined : JSON.parse(v); } catch { return undefined; }
  }

  set(key, v) {
    try { this.store?.setItem(this.ns + key, JSON.stringify(v)); } catch { /* места нет - не страшно */ }
  }

  async cached(key, fn) {
    try {
      const v = await fn();
      this.offline = false;
      this.set(key, v);
      return v;
    } catch (e) {
      if (e instanceof NetworkError) {
        const c = this.get(key);
        if (c !== undefined) { this.offline = true; return c; }
      }
      throw e;
    }
  }

  clear() {
    try {
      for (let i = this.store.length - 1; i >= 0; i--) {
        const k = this.store.key(i);
        if (k?.startsWith(this.ns)) this.store.removeItem(k);
      }
    } catch { /* нет доступа */ }
  }

  get invite() { return this.inner.invite; }
  set invite(v) { this.inner.invite = v; }
  authenticate(uid, signSk) { this.inner.authenticate?.(uid, signSk); }

  read(path) { return this.cached('f:' + path, () => this.inner.read(path)); }
  list(dir) { return this.cached('d:' + dir, () => this.inner.list(dir)); }
  people() { return this.cached('people', () => this.inner.people()); }
  prelogin(uid) { return this.cached('pre:' + uid, () => this.inner.prelogin(uid)); }
  // Ответ входа - это зашифрованный файл участника; без сети пароль проверит расшифровка
  login(uid, authKey) { return this.cached('login:' + uid, () => this.inner.login(uid, authKey)); }
  status() { return this.inner.status(); }
  setup(p) { return this.inner.setup(p); }
  createInvite() { return this.inner.createInvite(); }

  async write(path, text, rev) {
    const newRev = await this.inner.write(path, text, rev);
    this.set('f:' + path, { text, rev: newRev });
    return newRev;
  }

  async remove(path) {
    await this.inner.remove(path);
    this.set('f:' + path, null);
  }
}
