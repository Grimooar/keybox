// Сопоставление записи с адресом вкладки. Чистые функции, без браузера (проверяются в tests/ext.test.mjs).
// Правило намеренно строгое: хост записи должен совпасть с хостом вкладки (www. не в счёт), порт тоже.
// Поддомены и «родственные» домены НЕ считаются совпадением: без списка публичных суффиксов
// нельзя отличить shop.example.com от evil.github.io.

export function parseHttp(uri) {
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(uri) ? uri : 'https://' + uri);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u : null;
  } catch { return null; }
}

const stripWww = h => h.replace(/^www\./, '');

// Подставлять можно только на https (http - только localhost, для разработки)
export function fillable(tabUrl) {
  const u = parseHttp(tabUrl || '');
  if (!u) return false;
  if (u.protocol === 'https:') return true;
  return ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
}

export function matches(itemUri, tabUrl) {
  const a = parseHttp(itemUri || '');
  const b = parseHttp(tabUrl || '');
  if (!a || !b || !fillable(tabUrl)) return false;
  if (stripWww(a.hostname) !== stripWww(b.hostname)) return false;
  return (a.port || '') === (b.port || '') || (!a.port && b.port === '') ;
}

export const itemMatches = (item, tabUrl) => (item.uris || []).some(u => matches(u, tabUrl));
