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
  const u1 = 'a'.repeat(32), u2 = 'b'.repeat(32);
  const row = (ts, uid, status = 200) => ({ ts, uid, method: 'GET', route: 'api/f/vault/*', target: 'c'.repeat(24), status, ip: 'hash' });
  const keepAll = { before: 0, keep: 1000 };
  await db.addAudit(row(1000, u1), keepAll);
  await db.addAudit(row(2000, u2, 403), keepAll);
  await db.addAudit({ ...row(3000, null), ip: null }, keepAll); // без AUDIT_SALT адреса нет
  await db.addAudit(row(4000, u1), keepAll);
  const all = await db.listAudit({ uid: null, after: 0, since: 0, limit: 100 });
  assert.equal(all.length, 4);
  assert.deepEqual(Object.keys(all[0]).sort(), ['id', 'ip', 'method', 'route', 'status', 'target', 'ts', 'uid']);
  const mine = await db.listAudit({ uid: u1, after: 0, since: 0, limit: 100 });
  assert.deepEqual(mine.map(r => r.ts), [1000, 4000]);
  const page = await db.listAudit({ uid: null, after: all[0].id, since: 0, limit: 2 });
  assert.deepEqual(page.map(r => r.ts), [2000, 3000]);
  assert.deepEqual((await db.listAudit({ uid: null, after: 0, since: 3000, limit: 9 })).map(r => r.ts), [3000, 4000]);
  await db.addAudit(row(5000, u2), { before: 2500, keep: 1000 });
  assert.deepEqual((await db.listAudit({ uid: null, after: 0, since: 0, limit: 100 })).map(r => r.ts), [3000, 4000, 5000]);
  // Потолок строк: остаются последние keep
  await db.addAudit(row(6000, u2), { before: 0, keep: 2 });
  assert.deepEqual((await db.listAudit({ uid: null, after: 0, since: 0, limit: 100 })).map(r => r.ts), [5000, 6000]);
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
