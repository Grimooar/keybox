// Тесты участника-сервиса (Директор) и журнала сервера: node tests/director.test.mjs
// Клиент (ApiStorage + vault.js) говорит с настоящим обработчиком сервера через подменённый fetch.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
globalThis.hashwasm = require('../vendor/argon2.umd.min.js');

const C = await import('../js/crypto.js');
const { ApiStorage } = await import('../js/storage.js');
const V = await import('../js/vault.js');
const { handle } = await import('../server/src/handler.js');
const { MemoryStore } = await import('../server/src/db.js');

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ok  ', name); } catch (e) { console.log('  FAIL', name, '\n      ', e.stack); process.exitCode = 1; }
}
const rejects = async (p, re) => assert.rejects(p, e => (re.test(e.message) ? true : assert.fail('ошибка: ' + e.message)));

// Всё, что сервер пишет в консоль, - сюда: потом проверяем, что секретов там нет
const consoleLog = [];
for (const k of ['log', 'warn', 'error', 'info', 'debug']) {
  const orig = console[k];
  console[k] = (...a) => { consoleLog.push(a.map(String).join(' ')); if (k === 'log') orig(...a); };
}

const db = new MemoryStore();
const env = { SETUP_CODE: 'setup-code-dir', ALLOWED_ORIGINS: 'https://grimooar.github.io' };
const fetchFn = (url, opts) => handle(new Request(url, opts), db, env);
const BASE = 'https://api.test';
const TEAM = C.b64e(C.randomBytes(24));
const api = () => new ApiStorage(BASE, TEAM, fetchFn);
const dev = () => V.memorySeen();
const SECRET = 'Dir-Secret-' + C.randomHex(12);
const item = (name, password) => ({ id: C.randomHex(8), type: 'login', name, username: 'robot', password, uris: ['https://example.com'], notes: '' });

let owner, dir, general, dirCol, other;

await test('сервис: заявка помечена, админ принимает с флагом', async () => {
  owner = await V.createTeam(api(), { teamName: 'Студия', userName: 'Владелец', password: 'owner-pass', seen: dev(), setup: { setupCode: env.SETUP_CODE, teamHash: await C.sha256b64(TEAM) } });
  general = owner.collections().find(c => c.all).cid;
  await owner.saveItem(general, item('Общий сайт', 'general-pw-1'));
  other = await owner.createCollection('Бухгалтерия', false, []);
  await owner.saveItem(other, item('Банк', 'bank-pw-1'));

  const s = api();
  s.invite = (await owner.s.createInvite()).token;
  dir = await V.joinTeam(s, { userName: 'Директор', password: C.b64e(C.randomBytes(24)), seen: dev(), expectedTeamCode: await V.teamCode(owner.org), kind: 'service' });
  await owner.refresh();
  const p = (await owner.pendingUsers()).find(x => x.uid === dir.me.uid);
  assert.equal(p.service, true);
  await owner.approve(dir.me.uid, p.code, [], { service: true });
  dirCol = await owner.createCollection('Директор', false, [dir.me.uid]);
  await dir.refresh();
  assert.equal(dir.role, 'member');
  assert.equal(dir.isService, true);
});

await test('сервис видит только свою коллекцию: ни «для всех», ни личного сейфа', async () => {
  const cols = dir.collections();
  assert.deepEqual(cols.map(c => c.cid), [dirCol]);
  assert.ok(!owner.org.collections[general].wraps[dir.me.uid], 'ключ коллекции «для всех» не выдан');
  assert.ok(!owner.org.collections[other].wraps[dir.me.uid]);
  // Сервер не отдаёт файлы мимо клиента
  for (const cid of [general, other, V.personalCid(dir.me.uid)]) {
    const r = await dir.s.read('vault/' + cid + '.json').catch(e => e);
    assert.equal(r.status, 403, cid);
  }
  await dir.loadAll();
  assert.equal(dir.allItems().length, 0);
});

await test('сервис создаёт записи в своей коллекции', async () => {
  await dir.saveItem(dirCol, item('Новый сервис', SECRET));
  await owner.refresh();
  await owner.loadAll();
  const it = owner.allItems().find(i => i.name === 'Новый сервис');
  assert.equal(it.password, SECRET);
  assert.equal(it.updatedBy, dir.me.uid);
});

await test('сервису нельзя: личный сейф, отправки, чужие файлы участников', async () => {
  await rejects(dir.saveItem(dir.personalCid, item('Тайник', 'x')), /Нет доступа|Участнику-сервису/);
  // Сырой запрос мимо проверки клиента
  const r = await dir.s.req('POST', 'api/sends', JSON.stringify({ body: 'x'.repeat(10) }));
  assert.equal(r.r.status, 403);
  assert.match(r.data.error, /отправка/);
  const u = await dir.s.read('users/' + owner.me.uid + '.json').catch(e => e);
  assert.equal(u.status, 403);
  // Свой файл - можно (смена мастер-пароля при восстановлении)
  assert.ok(await dir.s.read('users/' + dir.me.uid + '.json'));
  // Приглашения и файл команды - как у обычного участника: нельзя
  await rejects(dir.s.createInvite(), /Только для владельца/);
});

await test('сервис не становится админом и не теряет флаг', async () => {
  await rejects(owner.setRole(dir.me.uid, 'admin'), /сервис/);
  // Подписанный владельцем файл без флага сервер не принимает
  await rejects(owner.updateOrg(d => { delete d.members[dir.me.uid].service; }), /сервис/);
  // Флаг у админа - подделка
  await rejects(owner.updateOrg(d => { d.members[owner.me.uid].service = true; }), /проверку|подделан/);
  await owner.refresh();
  assert.equal(owner.org.members[dir.me.uid].service, true);
});

await test('коллекция «для всех» не открывается сервису, даже если ключ подложить', async () => {
  // Клиент владельца со старыми правилами выдал бы ключ всем - сервер такой файл не примет
  const d = structuredClone(owner.org);
  const k = owner.keys.get(general);
  d.collections[general].wraps[dir.me.uid] = await C.sealTo(dir.me.boxPk, k.key, `wrap:${d.orgId}:${general}:${k.ver}:${dir.me.uid}`);
  d.version += 1; d.signer = owner.me.uid; delete d.sig;
  d.sig = await C.signObj(owner.me.signSk, d);
  await rejects(owner.s.write(V.ORG, JSON.stringify(d), owner.orgRev), /не прошёл проверку/);
  // Сделать общую коллекцию «для выбранных» и добавить сервис - можно явно
  await owner.updateCollection(general, { all: false, members: [dir.me.uid] });
  await dir.refresh();
  assert.ok(dir.collections().some(c => c.cid === general));
  await owner.updateCollection(general, { all: true });
  await dir.refresh();
  assert.ok(!dir.collections().some(c => c.cid === general));
});

await test('удаление сервиса: доступ пропадает, ключ коллекции меняется', async () => {
  const ver = owner.org.collections[dirCol].keyVersion;
  await owner.removeMember(dir.me.uid);
  assert.equal(owner.org.collections[dirCol].keyVersion, ver + 1);
  await rejects(dir.refresh(), /удалили|удалён/);
  // Вернём для следующих тестов: новый участник-сервис
  const s = api();
  s.invite = (await owner.s.createInvite()).token;
  dir = await V.joinTeam(s, { userName: 'Директор', password: C.b64e(C.randomBytes(24)), seen: dev(), kind: 'service' });
  const p = (await owner.pendingUsers()).find(x => x.uid === dir.me.uid);
  await owner.approve(dir.me.uid, p.code, [dirCol], { service: true });
  await dir.refresh();
  assert.deepEqual(dir.collections().map(c => c.cid), [dirCol]);
});

await test('журнал: кто, что, когда - по каждому запросу, с отказами', async () => {
  const before = db.audit.length;
  await dir.refresh();
  await dir.loadAll();
  await dir.s.read('vault/' + other + '.json').catch(() => {});
  const rows = db.audit.slice(before);
  const vaultRead = rows.find(r => r.route === 'api/f/vault/*' && r.target === dirCol && r.uid === dir.me.uid);
  assert.ok(vaultRead && vaultRead.method === 'GET' && vaultRead.status === 200);
  const denied = rows.find(r => r.target === other);
  assert.equal(denied.status, 403);
  // Файл команды читается без подписи (по секрету команды) - uid в такой строке пустой
  assert.ok(rows.some(r => r.route === 'api/f/org.json' && r.uid === null && r.status === 200));
  assert.ok(rows.every(r => Number.isSafeInteger(r.ts) && r.ip && r.ip !== 'local'));
  // Неверный вход и отклонённая подпись тоже в журнале
  await V.unlock(api(), owner.me.uid, 'wrong-pass', dev()).catch(() => {});
  const bad = db.audit.at(-1);
  assert.deepEqual([bad.route, bad.uid, bad.status], ['api/login', owner.me.uid, 401]);
  db.attempts.clear();
});

await test('журнал: участник читает только свои строки, владелец - все', async () => {
  const mine = await dir.s.audit({ limit: 1000 });
  assert.ok(mine.length > 0 && mine.every(r => r.uid === dir.me.uid));
  const all = await owner.s.audit({ limit: 1000 });
  assert.ok(all.some(r => r.uid === owner.me.uid) && all.some(r => r.uid === dir.me.uid));
  // Постранично по id
  const page = await owner.s.audit({ after: all[0].id, limit: 2 });
  assert.deepEqual(page.map(r => r.id), [all[1].id, all[2].id]);
  const r = await dir.s.req('GET', 'api/audit?limit=abc');
  assert.equal(r.r.status, 400);
});

await test('журнал: адрес хранится только как HMAC, старые строки удаляются', async () => {
  await fetchFn(BASE + '/api/people', { headers: { 'X-KB-Team': TEAM, 'CF-Connecting-IP': '203.0.113.7' } });
  const row = db.audit.at(-1);
  assert.equal(row.route, 'api/people');
  assert.ok(!JSON.stringify(row).includes('203.0.113.7'));
  assert.notEqual(row.ip, (await fetchFn(BASE + '/api/people', { headers: { 'X-KB-Team': TEAM, 'CF-Connecting-IP': '203.0.113.8' } }), db.audit.at(-1).ip));
  // Срок хранения: строки старше AUDIT_DAYS уходят при попутной чистке
  db.audit.unshift({ id: 0, ts: Date.now() - 400 * 24 * 3600 * 1000, uid: null, method: 'GET', route: 'other', target: null, status: 404, ip: 'x' });
  const rnd = Math.random;
  Math.random = () => 0;
  try { await fetchFn(BASE + '/api/people', { headers: { 'X-KB-Team': TEAM } }); } finally { Math.random = rnd; }
  assert.ok(db.audit.every(a => a.id !== 0));
});

await test('журнал: сломанный журнал не ломает запросы', async () => {
  const add = db.addAudit;
  db.addAudit = async () => { throw new Error('no such table: audit'); };
  try { await dir.refresh(); } finally { db.addAudit = add; }
});

await test('в журнале нет секретов: ни паролей, ни шифртекста, ни подписей, ни секрета команды', async () => {
  await dir.saveItem(dirCol, item('Ещё сервис', SECRET + '-2'));
  const sid = C.randomHex(16);
  await owner.s.req('POST', 'api/sends', JSON.stringify({ id: sid, body: 'cipher-' + C.randomHex(8) }));
  await fetchFn(BASE + '/api/sends/' + sid, {});
  const dump = JSON.stringify(db.audit);
  const vaultBody = db.files.get('vault/' + dirCol).body;
  const ct = JSON.parse(vaultBody).data.ct;
  for (const bad of [SECRET, 'general-pw-1', 'bank-pw-1', TEAM, ct, sid, 'owner-pass']) assert.ok(!dump.includes(bad), 'в журнале: ' + bad.slice(0, 12));
  assert.ok(!/sig|authKey|X-KB/i.test(dump));
  const keys = new Set(db.audit.flatMap(Object.keys));
  assert.deepEqual([...keys].sort(), ['id', 'ip', 'method', 'route', 'status', 'target', 'ts', 'uid']);
});

await test('секрет записи не попадает в консоль сервера', async () => {
  assert.ok(consoleLog.every(l => !l.includes(SECRET) && !l.includes('general-pw-1') && !l.includes(TEAM)));
});

console.log(`\n${passed} тестов прошло${process.exitCode ? ', есть ошибки' : ''}`);
