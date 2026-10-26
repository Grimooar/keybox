// Генератор паролей, коды двухфакторки (TOTP) и импорт CSV

import { randomHex } from './crypto.js';

// ---------- генератор ----------

const SETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!@#$%^&*-_=+?',
};
const AMBIGUOUS = { lower: 'l', upper: 'IO', digits: '01' };

// Случайное число 0..n-1 без перекоса (отбрасываем «хвост»)
function randInt(n) {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limit);
  return buf[0] % n;
}

export function generatePassword({ length = 20, lower = true, upper = true, digits = true, symbols = true, ambiguous = false } = {}) {
  const sets = Object.entries({ lower, upper, digits, symbols })
    .filter(([, on]) => on)
    .map(([k]) => SETS[k] + (ambiguous ? AMBIGUOUS[k] || '' : ''));
  if (!sets.length) sets.push(SETS.lower);
  // По символу из каждой выбранной группы, остальное - из всех вместе
  const all = sets.join('');
  const chars = sets.map(s => s[randInt(s.length)]);
  while (chars.length < length) chars.push(all[randInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.slice(0, length).join('');
}

// Грубая оценка стойкости в битах
export function strength(pw) {
  if (!pw) return { bits: 0, label: '', level: 0 };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 20;
  if (/[а-яё]/i.test(pw)) pool += 33;
  let bits = Math.round(pw.length * Math.log2(Math.max(pool, 2)));
  if (/^(.)\1+$/.test(pw) || /^(123|qwe|pass|пароль)/i.test(pw)) bits = Math.min(bits, 10);
  const level = bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { bits, level, label: ['', 'слабый', 'средний', 'хороший', 'отличный'][level] };
}

// ---------- TOTP ----------

function base32Decode(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = s.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const i = alphabet.indexOf(ch);
    if (i < 0) throw new Error('Неверный секрет 2FA');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

// Принимает и секрет, и ссылку otpauth://
export function parseTotp(input) {
  const s = (input || '').trim();
  if (!s) return null;
  if (s.startsWith('otpauth://')) {
    const u = new URL(s);
    return {
      secret: u.searchParams.get('secret') || '',
      digits: Number(u.searchParams.get('digits')) || 6,
      period: Number(u.searchParams.get('period')) || 30,
      algorithm: (u.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace('SHA', 'SHA-'),
    };
  }
  return { secret: s, digits: 6, period: 30, algorithm: 'SHA-1' };
}

export async function totpCode(input, now = Date.now()) {
  const p = parseTotp(input);
  if (!p) return null;
  const key = await crypto.subtle.importKey('raw', base32Decode(p.secret), { name: 'HMAC', hash: p.algorithm }, false, ['sign']);
  const counter = Math.floor(now / 1000 / p.period);
  const msg = new DataView(new ArrayBuffer(8));
  msg.setUint32(0, Math.floor(counter / 0x100000000));
  msg.setUint32(4, counter >>> 0);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const o = h[h.length - 1] & 15;
  const bin = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return {
    code: String(bin % 10 ** p.digits).padStart(p.digits, '0'),
    left: p.period - Math.floor(now / 1000) % p.period,
    period: p.period,
  };
}

// ---------- CSV ----------

export function parseCsv(text) {
  const rows = [];
  let row = [], field = '', q = false;
  text = text.replace(/^﻿/, '');
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.some(f => f.trim()));
}

// Bitwarden, Chrome/Edge/Яндекс, Firefox и похожие - определяем по заголовкам
export function importCsv(text) {
  const [head, ...rows] = parseCsv(text);
  if (!head) return [];
  const idx = {};
  head.forEach((h, i) => { idx[h.trim().toLowerCase()] = i; });
  const pick = (r, ...names) => {
    for (const n of names) if (idx[n] != null && r[idx[n]]) return r[idx[n]].trim();
    return '';
  };
  const out = [];
  for (const r of rows) {
    const type = pick(r, 'type');
    if (type && !['login', 'note'].includes(type)) continue;
    const uri = pick(r, 'login_uri', 'url', 'uri', 'website', 'web site');
    const name = pick(r, 'name', 'title') || hostOf(uri) || 'Без названия';
    const it = {
      id: randomHex(8),
      type: type === 'note' ? 'note' : 'login',
      name,
      username: pick(r, 'login_username', 'username', 'login', 'email'),
      password: pick(r, 'login_password', 'password'),
      uris: uri ? uri.split(',').map(s => s.trim()).filter(Boolean) : [],
      totp: pick(r, 'login_totp', 'totp', 'otpauth'),
      notes: pick(r, 'notes', 'note', 'extra', 'comments'),
      favorite: pick(r, 'favorite') === '1',
    };
    if (it.type === 'login' && !it.username && !it.password) continue;
    out.push(it);
  }
  return out;
}

export function hostOf(uri) {
  try { return new URL(/^[a-z]+:\/\//i.test(uri) ? uri : 'https://' + uri).hostname.replace(/^www\./, ''); } catch { return ''; }
}

// Ссылка безопасна для перехода (не javascript: и т.п.)
export function safeUrl(uri) {
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(uri) ? uri : 'https://' + uri);
    return ['http:', 'https:'].includes(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
}
