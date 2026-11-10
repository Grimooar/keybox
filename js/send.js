// Одноразовая отправка секрета (как Bitwarden Send).
// Текст шифруется на устройстве AES-256-GCM; ключ - только во фрагменте ссылки (#), его не видит сервер.
// AD = id ссылки: шифртекст нельзя подсунуть под другую ссылку.
import { encryptBytes, decryptBytes, randomBytes, randomHex, b64e, b64d } from './crypto.js';

export const SEND_AD = id => 'send:' + id;
export const TTL_OPTIONS = [[3600, '1 час'], [86400, '1 день'], [7 * 86400, '7 дней']];

export async function sealSend(text, id = randomHex(16)) {
  const key = randomBytes(32);
  const box = await encryptBytes(key, new TextEncoder().encode(text), SEND_AD(id));
  return { id, key: b64e(key), body: JSON.stringify(box) };
}

export async function openSend(id, keyB64, body) {
  const key = b64d(keyB64);
  if (key.length !== 32) throw new Error('Неверная ссылка');
  const box = JSON.parse(body);
  return new TextDecoder().decode(await decryptBytes(key, box, SEND_AD(id)));
}

export function sendLink(base, id, keyB64) {
  return new URL('send.html', base).href.split('#')[0] + '#' + id + '.' + keyB64;
}

export function parseFragment(hash) {
  const m = /^#?([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/.exec(hash || '');
  return m ? { id: m[1], key: m[2] } : null;
}

// storage - ApiStorage (или CachedStorage над ним) после входа: запрос подписывается участником
export async function createSend(storage, text, { ttlSec = 86400, views = 1, base = globalThis.location?.href } = {}) {
  if (!text) throw new Error('Пустой текст');
  const api = storage.inner ?? storage;
  const s = await sealSend(text);
  const { r, data } = await api.req('POST', 'api/sends', JSON.stringify({ id: s.id, body: s.body, ttlSec, views }));
  if (r.status !== 201) throw new Error(data.error || 'Сервер ответил ' + r.status);
  return { link: sendLink(base, data.id, s.key), id: data.id, expires: data.expires };
}

// Получатель: без аккаунта и секрета команды. null - ссылка недействительна или уже использована
export async function fetchSend(id, keyB64, { apiUrl, fetchFn = (...a) => globalThis.fetch(...a) }) {
  const r = await fetchFn(apiUrl.replace(/\/+$/, '') + '/api/sends/' + id, { method: 'GET', cache: 'no-store', referrerPolicy: 'no-referrer' });
  if (r.status === 404) return null;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'Сервер ответил ' + r.status);
  return { text: await openSend(id, keyB64, data.body), viewsLeft: data.viewsLeft };
}
