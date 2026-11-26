// SQL хранилища D1 на настоящем SQLite (node:sqlite, Node 22.5+): node tests/d1.test.mjs
// Проверяет schema.sql и запросы D1Store без Cloudflare - через маленькую обёртку с интерфейсом D1.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const { D1Store } = await import('../server/src/db.js');

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ok  ', name); } catch (e) { console.log('  FAIL', name, '\n      ', e.stack); process.exitCode = 1; }
}

// Обёртка: prepare().bind().first()/run()/all() и batch() одной транзакцией, как у D1
function fakeD1(sqlite) {
  const stmt = (sql, args = []) => ({
    bind: (...a) => stmt(sql, a),
    first: async () => sqlite.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: sqlite.prepare(sql).all(...args) }),
    run: async () => ({ meta: { changes: Number(sqlite.prepare(sql).run(...args).changes) } }),
    exec: () => sqlite.prepare(sql).run(...args),
  });
  return {
    prepare: sql => stmt(sql),
    batch: async list => {
      sqlite.exec('BEGIN');
      try { for (const s of list) s.exec(); sqlite.exec('COMMIT'); } catch (e) { sqlite.exec('ROLLBACK'); throw e; }
    },
  };
}

const sqlite = new DatabaseSync(':memory:');
const schema = readFileSync(new URL('../server/schema.sql', import.meta.url), 'utf8');
sqlite.exec(schema);
sqlite.exec(schema); // повторное применение миграции безопасно (IF NOT EXISTS)
const db = new D1Store(fakeD1(sqlite));

await test('журнал: запись, выборка по участнику, постранично, чистка старого', async () => {
  const u1 = 'a'.repeat(32), u2 = 'b'.repeat(32), u3 = 'e'.repeat(32);
  const row = (ts, uid, status = 200) => ({ ts, uid, method: 'GET', route: 'api/f/vault/*', target: 'c'.repeat(24), status, ip: 'hash' });
  const keepAll = { before: 0, perDay: 1000, keep: 1000 };
  await db.addAudit(row(1000, u1), keepAll);
  await db.addAudit(row(2000, u2, 403), keepAll);
  assert.equal(await db.addAudit({ ...row(3000, u3), ip: '' }, keepAll), 'row'); // без AUDIT_SALT адрес - ''
  await db.addAudit(row(4000, u1), keepAll);
  const all = await db.listAudit({ uid: null, after: 0, since: 0, limit: 100 });
  assert.equal(all.length, 4);
  assert.deepEqual(Object.keys(all[0]).sort(), ['id', 'ip', 'method', 'route', 'status', 'target', 'ts', 'uid']);
  const mine = await db.listAudit({ uid: u1, after: 0, since: 0, limit: 100 });
  assert.deepEqual(mine.map(r => r.ts), [1000, 4000]);
  const page = await db.listAudit({ uid: null, after: all[0].id, since: 0, limit: 2 });
  assert.deepEqual(page.map(r => r.ts), [2000, 3000]);
  assert.deepEqual((await db.listAudit({ uid: null, after: 0, since: 3000, limit: 9 })).map(r => r.ts), [3000, 4000]);
  await db.addAudit(row(5000, u2), { ...keepAll, before: 2500 });
  assert.deepEqual((await db.listAudit({ uid: null, after: 0, since: 0, limit: 100 })).map(r => r.ts), [3000, 4000, 5000]);
});

await test('журнал: потолок и квота - на участника, чужие строки не вытесняются', async () => {
  sqlite.exec('DELETE FROM audit; DELETE FROM audit_count');
  const boss = 'a'.repeat(32), noisy = 'b'.repeat(32);
  const row = (ts, uid) => ({ ts, uid, method: 'GET', route: 'api/people', target: null, status: 200, ip: '' });
  for (let i = 0; i < 4; i++) await db.addAudit(row(1000 + i, boss), { before: 0, perDay: 100, keep: 3, trimEvery: 1000 });
  for (let i = 0; i < 30; i++) await db.addAudit(row(2000 + i, noisy), { before: 0, perDay: 100, keep: 3, trimEvery: 1 });
  const left = await db.listAudit({ uid: null, after: 0, since: 0, limit: 100 });
  assert.deepEqual(left.filter(r => r.uid === boss).map(r => r.ts), [1000, 1001, 1002, 1003]);
  assert.deepEqual(left.filter(r => r.uid === noisy).map(r => r.ts), [2027, 2028, 2029]);
  // Квота в сутки: 2 строки, третья - отметка audit-quota, дальше ничего; новые сутки - заново
  const DAY = 24 * 3600 * 1000, q = { before: 0, perDay: 2, keep: 100 };
  const res = [];
  for (let i = 0; i < 5; i++) res.push(await db.addAudit(row(10 * DAY + i, noisy), q));
  assert.deepEqual(res, ['row', 'row', 'quota', 'quota', 'quota']);
  const today = await db.listAudit({ uid: noisy, after: 0, since: 10 * DAY, limit: 100 });
  assert.deepEqual(today.map(r => r.route), ['api/people', 'api/people', 'audit-quota']);
  assert.equal(await db.addAudit(row(11 * DAY, noisy), q), 'row');
  assert.equal(await db.addAudit(row(11 * DAY, boss), q), 'row');
});

await test('миграция: старая таблица audit (ip NOT NULL без умолчания или ip nullable) принимает запись сервера', async () => {
  for (const ipCol of ['ip TEXT NOT NULL', 'ip TEXT']) {
    const old = new DatabaseSync(':memory:');
    old.exec(`CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, uid TEXT, method TEXT NOT NULL, route TEXT NOT NULL, target TEXT, status INTEGER NOT NULL, ${ipCol})`);
    old.exec(schema); // миграция поверх: IF NOT EXISTS таблицу audit не меняет, добавляет новые
    const s = new D1Store(fakeD1(old));
    assert.equal(await s.addAudit({ ts: 1, uid: 'a'.repeat(32), method: 'GET', route: 'api/people', target: null, status: 200, ip: '' }, { before: 0, perDay: 10, keep: 10 }), 'row');
    assert.equal((await s.listAudit({ uid: null, after: 0, since: 0, limit: 9 }))[0].ip, '');
  }
});

await test('счётчик отказов: одна строка на день, путь и код; старые дни удаляются', async () => {
  for (let i = 0; i < 50; i++) await db.countDenied({ day: 10, route: 'other', status: 403 }, 0);
  await db.countDenied({ day: 10, route: 'api/people', status: 403 }, 0);
  await db.countDenied({ day: 11, route: 'other', status: 404 }, 0);
  assert.deepEqual((await db.listDenied({ sinceDay: 0 })).map(r => ({ ...r })), [
    { day: 10, route: 'api/people', status: 403, n: 1 }, { day: 10, route: 'other', status: 403, n: 50 }, { day: 11, route: 'other', status: 404, n: 1 }]);
  assert.equal((await db.listDenied({ sinceDay: 11 })).length, 1);
  await db.countDenied({ day: 12, route: 'other', status: 404 }, 11);
  assert.deepEqual((await db.listDenied({ sinceDay: 0 })).map(r => r.day), [11, 12]);
});

await test('файлы, мета и отправки работают на той же схеме', async () => {
  assert.equal(await db.put('vault/x', 'b1', null), 1);
  assert.equal(await db.put('vault/x', 'b2', 1), 2);
  assert.equal(await db.put('vault/x', 'b3', 1), null);
  assert.equal(await db.metaInit('pepper', 'p'), true);
  assert.equal(await db.meta('pepper'), 'p');
  await db.addSend('d'.repeat(32), 'ct', 'a'.repeat(32), 10_000, 1, 0);
  assert.equal((await db.takeSend('d'.repeat(32), 1)).body, 'ct');
  assert.equal(await db.takeSend('d'.repeat(32), 1), null);
});

console.log(`\n${passed} тестов прошло${process.exitCode ? ', есть ошибки' : ''}`);
