// Проверка паролей: слабые, повторяющиеся, старые, утёкшие. Без DOM.
import { strength } from './tools.js';

export const OLD_DAYS = 180;
const DAY = 86400000;
export const HIBP_URL = 'https://api.pwnedpasswords.com/range/';

const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
async function digest(algo, s) {
  return hex(await crypto.subtle.digest(algo, new TextEncoder().encode(s)));
}
export const sha256 = s => digest('SHA-256', s);
export async function sha1Upper(s) { return (await digest('SHA-1', s)).toUpperCase(); }

// -> { weak:[{item,score}], reused:[[items]], old:[items], total }
export async function analyze(items, now = Date.now()) {
  const logins = (items || []).filter(i => i && i.type === 'login' && typeof i.password === 'string' && i.password);
  const weak = [], old = [], groups = new Map();
  for (const item of logins) {
    const st = strength(item.password);
    if (st.level <= 1) weak.push({ item, score: st.bits });
    const ts = item.updatedAt || item.createdAt;
    if (ts && now - ts > OLD_DAYS * DAY) old.push(item);
    const key = await sha256(item.password); // в ключах Map только хеш
    (groups.get(key) || groups.set(key, []).get(key)).push(item);
  }
  weak.sort((a, b) => a.score - b.score);
  const reused = [...groups.values()].filter(g => g.length > 1).sort((a, b) => b.length - a.length);
  return { weak, reused, old, total: logins.length };
}

const cache = new Map(); // SHA-1 пароля -> число утечек; живёт только в памяти сессии
export function clearBreachCache() { cache.clear(); }

// Число утечек, 0 - не найден, null - не удалось проверить.
// Наружу уходят только первые 5 hex-символов SHA-1 (k-anonymity).
export async function breachCount(password, fetchFn = globalThis.fetch) {
  try {
    const sha = await sha1Upper(password);
    if (cache.has(sha)) return cache.get(sha);
    const prefix = sha.slice(0, 5), suffix = sha.slice(5);
    const res = await fetchFn(HIBP_URL + prefix, { headers: { 'Add-Padding': 'true' }, credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!res.ok) return null;
    let n = 0;
    for (const line of (await res.text()).split(/\r?\n/)) {
      const [suf, cnt] = line.trim().split(':');
      if (suf && suf.toUpperCase() === suffix) { n = parseInt(cnt, 10) || 0; break; }
    }
    cache.set(sha, n);
    return n;
  } catch { return null; }
}

// Проверка списка с ограничением параллелизма. -> Map(item -> число | null)
export async function checkBreaches(items, { onProgress, fetchFn, concurrency = 2 } = {}) {
  const res = new Map();
  let i = 0, done = 0;
  const worker = async () => {
    while (i < items.length) {
      const it = items[i++];
      res.set(it, await breachCount(it.password, fetchFn));
      onProgress?.(++done, items.length);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return res;
}
