// Хранилища файлов. У всех одинаковый интерфейс:
//   read(path)             -> { text, rev } | null
//   write(path, text, rev) -> newRev   (rev = null - только создать новый файл)
//   list(dir)              -> [имена файлов]
//   remove(path)
// Если файл изменили одновременно с другого устройства, write бросает ConflictError,
// и вызывающий код перечитывает файл и повторяет операцию.

export class ConflictError extends Error {}
export class NetworkError extends Error {}

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

// Заголовок Dropbox-API-Arg - только ASCII
function apiArg(obj) {
  return JSON.stringify(obj).replace(/[\u007f-￿]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

async function dbxFail(r) {
  let summary = '';
  try { summary = (await r.json()).error_summary || ''; } catch { /* тело не JSON */ }
  const e = new Error(`Dropbox: ${r.status} ${summary}`.trim());
  e.status = r.status;
  e.summary = summary;
  return e;
}

export class DropboxStorage {
  constructor(auth, root) {
    this.auth = auth;
    this.root = '/' + root.replace(/^\/+|\/+$/g, '');
  }

  p(path) { return this.root + '/' + path; }

  async rpc(endpoint, body) {
    return this.auth.fetch('https://api.dropboxapi.com/2/' + endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async read(path) {
    const r = await this.auth.fetch('https://content.dropboxapi.com/2/files/download', {
      method: 'POST',
      headers: { 'Dropbox-API-Arg': apiArg({ path: this.p(path) }) },
    });
    if (r.status === 409) {
      const e = await dbxFail(r);
      if (e.summary.includes('not_found')) return null;
      throw e;
    }
    if (!r.ok) throw await dbxFail(r);
    const meta = JSON.parse(r.headers.get('Dropbox-API-Result'));
    return { text: await r.text(), rev: meta.rev };
  }

  async write(path, text, rev) {
    const arg = {
      path: this.p(path),
      mode: rev ? { '.tag': 'update', update: rev } : 'add',
      autorename: false,
      mute: true,
      strict_conflict: true,
    };
    const r = await this.auth.fetch('https://content.dropboxapi.com/2/files/upload', {
      method: 'POST',
      headers: { 'Dropbox-API-Arg': apiArg(arg), 'Content-Type': 'application/octet-stream' },
      body: new Blob([text]),
    });
    if (r.status === 409) {
      const e = await dbxFail(r);
      if (e.summary.includes('conflict')) throw new ConflictError(path);
      throw e;
    }
    if (!r.ok) throw await dbxFail(r);
    return (await r.json()).rev;
  }

  async list(dir) {
    let r = await this.rpc('files/list_folder', { path: this.p(dir) });
    const names = [];
    for (;;) {
      if (r.status === 409) {
        const e = await dbxFail(r);
        if (e.summary.includes('not_found')) return names;
        throw e;
      }
      if (!r.ok) throw await dbxFail(r);
      const page = await r.json();
      for (const e of page.entries) if (e['.tag'] === 'file') names.push(e.name);
      if (!page.has_more) return names;
      r = await this.rpc('files/list_folder/continue', { cursor: page.cursor });
    }
  }

  async remove(path) {
    const r = await this.rpc('files/delete_v2', { path: this.p(path) });
    if (r.status === 409) {
      const e = await dbxFail(r);
      if (e.summary.includes('not_found')) return;
      throw e;
    }
    if (!r.ok) throw await dbxFail(r);
  }
}

// Обёртка: запоминает последние прочитанные (зашифрованные) файлы,
// чтобы без интернета можно было хотя бы смотреть пароли.
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

  read(path) { return this.cached('f:' + path, () => this.inner.read(path)); }
  list(dir) { return this.cached('d:' + dir, () => this.inner.list(dir)); }

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
