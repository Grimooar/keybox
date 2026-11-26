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

await test('секрет записи не попадает в консоль сервера', async () => {
  assert.ok(consoleLog.every(l => !l.includes(SECRET) && !l.includes('general-pw-1') && !l.includes(TEAM)));
});

console.log(`\n${passed} тестов прошло${process.exitCode ? ', есть ошибки' : ''}`);
