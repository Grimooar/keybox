// Вход в Dropbox через OAuth 2 PKCE - без серверной части и без секрета приложения.
// Хранится только refresh-токен: он даёт доступ к файлам, но сами файлы зашифрованы.

import { NetworkError } from './storage.js';
import { b64e, randomBytes, randomHex } from './crypto.js';

const LS_KEY = 'kb.dropbox';
const PKCE_KEY = 'kb.pkce';

function load() {
  try { return JSON.parse(localStorage.getItem(LS_KEY) || 'null'); } catch { return null; }
}

export function redirectUri() {
  return location.origin + location.pathname.replace(/index\.html$/, '');
}

const wait = ms => new Promise(r => setTimeout(r, ms));

export class DropboxAuth {
  constructor(appKey) {
    this.appKey = appKey;
    this.state = load();
  }

  get connected() { return !!this.state?.refresh_token; }

  save() { localStorage.setItem(LS_KEY, JSON.stringify(this.state)); }

  async begin() {
    const verifier = b64e(randomBytes(48));
    const challenge = b64e(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    const st = randomHex(16);
    sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, st }));
    location.assign('https://www.dropbox.com/oauth2/authorize?' + new URLSearchParams({
      client_id: this.appKey,
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      redirect_uri: redirectUri(),
      token_access_type: 'offline',
      state: st,
    }));
  }

  // Вызывается при загрузке страницы. true - если это был возврат из Dropbox.
  async handleRedirect() {
    const q = new URLSearchParams(location.search);
    if (!q.has('code') && !q.has('error')) return false;
    history.replaceState(null, '', location.pathname);
    if (q.has('error')) throw new Error('Dropbox: ' + (q.get('error_description') || q.get('error')));
    const p = JSON.parse(sessionStorage.getItem(PKCE_KEY) || 'null');
    sessionStorage.removeItem(PKCE_KEY);
    if (!p || p.st !== q.get('state')) throw new Error('Ответ Dropbox не совпал с запросом, попробуйте ещё раз');
    const tok = await this.tokenRequest({
      code: q.get('code'),
      grant_type: 'authorization_code',
      code_verifier: p.verifier,
      client_id: this.appKey,
      redirect_uri: redirectUri(),
    });
    this.state = {
      refresh_token: tok.refresh_token,
      access_token: tok.access_token,
      expires_at: Date.now() + tok.expires_in * 1000 - 60000,
    };
    this.save();
    return true;
  }

  async tokenRequest(params) {
    let r;
    try {
      r = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', body: new URLSearchParams(params) });
    } catch (e) {
      throw new NetworkError(e.message);
    }
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      if (body.error === 'invalid_grant') { this.state = null; localStorage.removeItem(LS_KEY); }
      throw new Error('Dropbox: ' + (body.error_description || body.error || r.status));
    }
    return body;
  }

  async token() {
    if (!this.state) throw new Error('Dropbox не подключён');
    if (this.state.access_token && Date.now() < this.state.expires_at) return this.state.access_token;
    const tok = await this.tokenRequest({
      grant_type: 'refresh_token',
      refresh_token: this.state.refresh_token,
      client_id: this.appKey,
    });
    this.state.access_token = tok.access_token;
    this.state.expires_at = Date.now() + tok.expires_in * 1000 - 60000;
    this.save();
    return tok.access_token;
  }

  async fetch(url, opts = {}) {
    for (let attempt = 0; ; attempt++) {
      const headers = { ...opts.headers, Authorization: 'Bearer ' + await this.token() };
      let r;
      try {
        r = await fetch(url, { ...opts, headers });
      } catch (e) {
        throw new NetworkError(e.message);
      }
      if (r.status === 401 && attempt === 0) { this.state.expires_at = 0; continue; }
      if ((r.status === 429 || r.status >= 500) && attempt < 4) {
        await wait((Number(r.headers.get('Retry-After')) || 2 ** attempt) * 1000);
        continue;
      }
      return r;
    }
  }

  async disconnect() {
    try {
      if (this.state) await this.fetch('https://api.dropboxapi.com/2/auth/token/revoke', { method: 'POST' });
    } catch { /* токен всё равно забываем */ }
    this.state = null;
    localStorage.removeItem(LS_KEY);
  }
}
