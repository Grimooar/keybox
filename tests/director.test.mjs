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
const env = { SETUP_CODE: 'setup-code-dir', ALLOWED_ORIGINS: 'https://grimooar.github.io', AUDIT_SALT: 'audit-salt-' + C.randomHex(8) };
// fakeIp - адрес клиента, как его подставляет Cloudflare (CF-Connecting-IP), для подписанных запросов через ApiStorage
let fakeIp = null;
const fetchFn = (url, opts = {}) => handle(new Request(url, fakeIp ? { ...opts, headers: { ...Object.fromEntries(new Headers(opts.headers)), 'CF-Connecting-IP': fakeIp } } : opts), db, env);
const deniedN = (route, status) => [...db.denied].filter(([k]) => { const [, r, s] = JSON.parse(k); return r === route && s === status; }).reduce((a, [, n]) => a + n, 0);
const BASE = 'https://api.test';
const TEAM = C.b64e(C.randomBytes(24));
const api = () => new ApiStorage(BASE, TEAM, fetchFn);
const dev = () => V.memorySeen();
const SECRET = 'Dir-Secret-' + C.randomHex(12);
const item = (name, password) => ({ id: C.randomHex(8), type: 'login', name, username: 'robot', password, uris: ['https://example.com'], notes: '' });
// Файл команды, подписанный владельцем мимо проверок клиента (так пишет старый или чужой клиент)
async function forgedOrg(s, mutate) {
  await s.refresh();
  const d = structuredClone(s.org);
  await mutate(d);
  d.version += 1; d.signer = s.me.uid; delete d.sig;
  d.sig = await C.signObj(s.me.signSk, d);
  return s.s.write(V.ORG, JSON.stringify(d), s.orgRev);
}

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
  // Пока есть коллекция «для всех», сервис не принять: старые клиенты сочли бы файл команды подделанным
  await rejects(owner.approve(dir.me.uid, p.code, [], { service: true }), /не совмещаются/);
  const raw = { name: 'Директор', role: 'member', boxPk: dir.me.boxPk, signPk: dir.me.signPk, addedAt: Date.now(), service: true };
  await rejects(forgedOrg(owner, d => { d.members[dir.me.uid] = raw; }), /не совмещаются/);
  await owner.refresh();
  assert.ok(!owner.org.members[dir.me.uid]);
  await owner.updateCollection(general, { all: false, members: [] });
  await owner.approve(dir.me.uid, p.code, [], { service: true });
  dirCol = await owner.createCollection('Директор', false, [dir.me.uid]);
  // И наоборот: при сервисе в команде новую коллекцию «для всех» не создать
  await rejects(owner.createCollection('Все', true), /не совмещаются/);
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
  // Клиент со старыми правилами сделал бы коллекцию «для всех» с ключом каждому - сервер объясняет, почему нет
  const k = owner.keys.get(general);
  await rejects(forgedOrg(owner, async d => {
    d.collections[general].all = true;
    d.collections[general].wraps[dir.me.uid] = await C.sealTo(dir.me.boxPk, k.key, `wrap:${d.orgId}:${general}:${k.ver}:${dir.me.uid}`);
  }), /не совмещаются.*старые версии/);
  // Ключ сервису от коллекции «для всех» - подделка и для нового клиента
  const d = structuredClone(owner.org);
  d.collections[general].all = true;
  d.collections[general].wraps[dir.me.uid] = 'x';
  await rejects(V.verifyOrg(d, owner.me.pin, null), /подделан/);
  // Сделать коллекцию «для выбранных» и добавить сервис - можно явно
  await owner.updateCollection(general, { members: [dir.me.uid] });
  await dir.refresh();
  assert.ok(dir.collections().some(c => c.cid === general));
  await rejects(owner.updateCollection(general, { all: true }), /не совмещаются/);
  await owner.updateCollection(general, { members: [] });
  await dir.refresh();
  assert.ok(!dir.collections().some(c => c.cid === general));
});

await test('файл команды новее клиента: «обновите», а не «подделан»', async () => {
  await rejects(V.verifyOrg({ ...owner.org, v: 2 }, owner.me.pin, null), /Обновите/);
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

await test('журнал: кто, что, когда - по каждому запросу проверенного участника', async () => {
  const before = db.audit.length;
  await dir.refresh();
  await dir.loadAll();
  await dir.s.read('vault/' + other + '.json').catch(() => {});
  const rows = db.audit.slice(before);
  const vaultRead = rows.find(r => r.route === 'api/f/vault/*' && r.target === dirCol && r.uid === dir.me.uid);
  assert.ok(vaultRead && vaultRead.method === 'GET' && vaultRead.status === 200);
  // Отказ в доступе к чужой коллекции - тоже строка: подпись верная, участник известен
  const denied = rows.find(r => r.target === other);
  assert.deepEqual([denied.uid, denied.status], [dir.me.uid, 403]);
  // Файл команды читается без подписи (по секрету команды) - такой запрос строки не даёт
  assert.ok(rows.every(r => r.uid === dir.me.uid));
  assert.ok(rows.every(r => Number.isSafeInteger(r.ts) && r.ip && r.ip !== 'local'));
  // Неверный вход - только счётчик; верный - строка с uid
  const beforeBad = db.audit.length;
  await V.unlock(api(), owner.me.uid, 'wrong-pass', dev()).catch(() => {});
  assert.equal(db.audit.length, beforeBad);
  assert.ok(deniedN('api/login', 401) >= 1);
  db.attempts.clear();
  await V.unlock(api(), owner.me.uid, 'owner-pass', dev());
  const good = db.audit.findLast(r => r.route === 'api/login');
  assert.deepEqual([good.uid, good.target, good.status], [owner.me.uid, owner.me.uid, 200]);
});

const H = (extra = {}) => ({ 'X-KB-Team': TEAM, Origin: 'https://grimooar.github.io', ...extra });

await test('журнал: заявка с чужим uid и неверным приглашением - без строки', async () => {
  const fakeUid = C.randomHex(16);
  const before = db.audit.length;
  const r = await fetchFn(BASE + '/api/f/users/' + fakeUid + '.json', { method: 'PUT', headers: H({ 'X-KB-Invite': 'bad-token' }), body: '{}' });
  assert.ok(r.status >= 400);
  assert.equal(db.audit.length, before);
  assert.ok(db.audit.every(a => a.uid !== fakeUid && a.target !== fakeUid));
});

await test('журнал: верный секрет команды и мусорная подпись - ни одной строки, сколько ни шли', async () => {
  const before = db.audit.length, lastId = db.auditId;
  const was = deniedN('api/f/vault/*', 401);
  for (let i = 0; i < 300; i++) {
    const sig = C.b64e(C.randomBytes(64));
    await fetchFn(BASE + '/api/f/vault/' + general + '.json', { headers: H({ 'X-KB-Auth': `${owner.me.uid}:${Date.now()}:${sig}` }) });
  }
  await fetchFn(BASE + '/api/people', { headers: H() });
  await fetchFn(BASE + '/api/prelogin/' + owner.me.uid, { headers: H() });
  await fetchFn(BASE + '/api/f/org.json', { headers: H() });
  assert.equal(db.audit.length, before);
  assert.equal(db.auditId, lastId);
  assert.equal(deniedN('api/f/vault/*', 401) - was, 300);
});

await test('журнал: без секрета команды и на неизвестный путь - только счётчик, не строки', async () => {
  const before = db.audit.length;
  for (let i = 0; i < 50; i++) await fetchFn(BASE + '/api/anything' + i, {});
  for (let i = 0; i < 20; i++) await fetchFn(BASE + '/api/anything' + i, { headers: H() });
  for (let i = 0; i < 5; i++) await fetchFn(BASE + '/api/people', { headers: { 'X-KB-Team': 'wrong' } });
  await fetchFn(BASE + '/api/sends/' + C.randomHex(16), {});
  assert.equal(db.audit.length, before);
  const { rows, denied } = (await owner.s.req('GET', 'api/audit?limit=1')).data;
  assert.equal(rows.length, 1);
  const n = (route, status) => denied.filter(x => x.route === route && x.status === status).reduce((a, x) => a + x.n, 0);
  assert.equal(n('other', 403), 50);
  assert.equal(denied.filter(x => x.route === 'other').reduce((a, x) => a + x.n, 0), 70); // с секретом команды, но без подписи - 401
  assert.equal(n('api/people', 403), 5);
  assert.equal(n('api/sends/*', 404), 1);
  // Участнику счётчик не отдаётся
  assert.equal((await dir.s.req('GET', 'api/audit?limit=1')).data.denied, undefined);
});

await test('журнал: участник не вытесняет чужие строки (потолок на uid)', async () => {
  env.AUDIT_UID_ROWS = '5';
  env.AUDIT_TRIM_EVERY = '1';
  try {
    const ownerRows = () => db.audit.filter(a => a.uid === owner.me.uid).map(a => a.id);
    const keep = ownerRows();
    assert.ok(keep.length > 5);
    for (let i = 0; i < 40; i++) await dir.s.req('GET', 'api/audit?limit=1');
    assert.equal(db.audit.filter(a => a.uid === dir.me.uid).length, 5);
    assert.deepEqual(ownerRows(), keep);
    assert.ok(db.audit.filter(a => a.uid === dir.me.uid).every(a => a.route === 'api/audit'));
  } finally { delete env.AUDIT_UID_ROWS; delete env.AUDIT_TRIM_EVERY; }
});

await test('журнал: квота строк на участника в сутки, сверх - одна отметка и счётчик', async () => {
  const today = db.auditCount.get(dir.me.uid).n_day;
  env.AUDIT_UID_DAY = String(today + 3);
  try {
    const before = db.audit.length, was = deniedN('quota:api/audit', 200);
    for (let i = 0; i < 10; i++) await dir.s.req('GET', 'api/audit?limit=1');
    const rows = db.audit.slice(before);
    assert.deepEqual(rows.map(r => r.route), ['api/audit', 'api/audit', 'api/audit', 'audit-quota']);
    assert.ok(rows.every(r => r.uid === dir.me.uid));
    assert.equal(deniedN('quota:api/audit', 200) - was, 7);
    // Квота - своя у каждого: владелец пишется как обычно
    await owner.s.req('GET', 'api/audit?limit=1');
    assert.equal(db.audit.at(-1).uid, owner.me.uid);
  } finally { delete env.AUDIT_UID_DAY; }
});

await test('журнал: без AUDIT_SALT адрес - пустая строка', async () => {
  const salt = env.AUDIT_SALT;
  delete env.AUDIT_SALT;
  fakeIp = '203.0.113.9';
  try { await dir.s.req('GET', 'api/audit?limit=1'); } finally { env.AUDIT_SALT = salt; fakeIp = null; }
  assert.equal(db.audit.at(-1).uid, dir.me.uid);
  assert.equal(db.audit.at(-1).ip, '');
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
  fakeIp = '203.0.113.7';
  try {
    await dir.s.req('GET', 'api/audit?limit=1');
    const row = db.audit.at(-1);
    assert.deepEqual([row.route, row.uid], ['api/audit', dir.me.uid]);
    assert.ok(row.ip && !JSON.stringify(row).includes('203.0.113.7'));
    fakeIp = '203.0.113.8';
    await dir.s.req('GET', 'api/audit?limit=1');
    assert.notEqual(row.ip, db.audit.at(-1).ip);
  } finally { fakeIp = null; }
  // Срок хранения: строки старше AUDIT_DAYS уходят при попутной чистке
  db.audit.unshift({ id: 0, ts: Date.now() - 400 * 24 * 3600 * 1000, uid: owner.me.uid, method: 'GET', route: 'api/audit', target: null, status: 200, ip: 'x' });
  await dir.s.req('GET', 'api/audit?limit=1');
  assert.ok(db.audit.every(a => a.id !== 0));
});

await test('журнал: сломанный журнал не ломает запросы и считается в счётчике', async () => {
  const add = db.addAudit;
  const was = deniedN('audit-error:api/f/vault/*', 200);
  db.addAudit = async () => { throw new Error('NOT NULL constraint failed: audit.ip'); };
  try { await dir.refresh(); await dir.loadAll(); } finally { db.addAudit = add; }
  assert.ok(deniedN('audit-error:api/f/vault/*', 200) > was);
  // Нет и таблицы счётчика - запрос всё равно отвечает
  const count = db.countDenied;
  db.addAudit = db.countDenied = async () => { throw new Error('no such table'); };
  try { await dir.loadAll(); } finally { db.addAudit = add; db.countDenied = count; }
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
