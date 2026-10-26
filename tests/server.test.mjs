// Тесты сервера: node tests/server.test.mjs
// Клиент (ApiStorage + vault.js) говорит с настоящим обработчиком сервера через подменённый fetch.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
globalThis.hashwasm = require('../vendor/argon2.umd.min.js');

const C = await import('../js/crypto.js');
const { ApiStorage, ConflictError } = await import('../js/storage.js');
const V = await import('../js/vault.js');
const { handle } = await import('../server/src/handler.js');
const { MemoryStore } = await import('../server/src/db.js');

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ok  ', name); } catch (e) { console.log('  FAIL', name, '\n      ', e.stack); process.exitCode = 1; }
}
const rejects = async (p, re) => assert.rejects(p, e => (re.test(e.message) ? true : assert.fail('ошибка: ' + e.message)));
const item = (name, password = 'pw-' + name) => ({ id: C.randomHex(8), type: 'login', name, username: 'u', password, uris: [], notes: '' });

const db = new MemoryStore();
const env = { SETUP_CODE: 'setup-code-123', ALLOWED_ORIGINS: 'https://grimooar.github.io' };
const fetchFn = (url, opts) => handle(new Request(url, opts), db, env);
const BASE = 'https://api.test';
const TEAM = C.b64e(C.randomBytes(24));
const api = (team = TEAM) => new ApiStorage(BASE, team, fetchFn);
const dev = () => V.memorySeen();
// Сырой запрос мимо клиента - как сделал бы атакующий
const raw = (method, path, { body, headers = {} } = {}) => fetchFn(BASE + path, { method, body, headers: { 'X-KB-Team': TEAM, ...headers } });

let owner, alice, bob, general, ads, inviteToken;

await test('установка: без кода нельзя, с кодом - один раз', async () => {
  assert.equal((await api().status()).team, false);
  await rejects(V.createTeam(api(), { teamName: 'T', userName: 'X', password: 'p', seen: dev(), setup: { setupCode: 'wrong', teamHash: await C.sha256b64(TEAM) } }), /Неверный код/);
  owner = await V.createTeam(api(), { teamName: 'GearPoint', userName: 'Вова', password: 'owner-pass', seen: dev(), setup: { setupCode: env.SETUP_CODE, teamHash: await C.sha256b64(TEAM) } });
  general = owner.collections().find(c => c.all).cid;
  await owner.saveItem(general, item('Instagram'));
  await rejects(V.createTeam(api(), { teamName: 'T2', userName: 'Y', password: 'p', seen: dev(), setup: { setupCode: env.SETUP_CODE, teamHash: 'x'.repeat(43) } }), /уже создана/);
});

await test('без секрета команды сервер ничего не отдаёт', async () => {
  const s = api('wrong-team-secret');
  await rejects(s.people(), /Неверная ссылка/);
  await rejects(s.read(V.ORG), /Неверная ссылка/);
  const r = await fetchFn(BASE + '/api/f/org.json', { method: 'GET' });
  assert.equal(r.status, 403);
});

await test('вход по паролю: неверный пароль и блокировка после 8 попыток', async () => {
  await rejects(V.unlock(api(), owner.me.uid, 'wrong', dev()), /Неверный мастер-пароль/);
  const s = await V.unlock(api(), owner.me.uid, 'owner-pass', dev());
  assert.equal(s.role, 'owner');
  // Подбор: 8 неудач -> блокировка, даже верный пароль не пускает
  for (let i = 0; i < 8; i++) await rejects(V.unlock(api(), owner.me.uid, 'guess' + i, dev()), /Неверный|попыток/);
  await rejects(V.unlock(api(), owner.me.uid, 'owner-pass', dev()), /Слишком много неверных попыток/);
  await db.setFails(owner.me.uid, 0, 0); // снимаем блокировку для остальных тестов
});

await test('файл участника с зашифрованными ключами не отдаётся без пароля', async () => {
  const r = await raw('GET', '/api/f/users/' + owner.me.uid + '.json');
  assert.equal(r.status, 401);
  const pre = await (await raw('GET', '/api/prelogin/' + owner.me.uid)).json();
  assert.ok(pre.kdf && !pre.secret && !pre.authHash);
});

await test('вступление только по приглашению', async () => {
  const noInvite = api();
  await rejects(V.joinTeam(noInvite, { userName: 'Чужой', password: 'x-pass', seen: dev() }), /Нужен вход|Приглашение/);
  inviteToken = (await owner.s.createInvite()).token;
  const s = api();
  s.invite = inviteToken;
  alice = await V.joinTeam(s, { userName: 'Алиса', password: 'alice-pass', seen: dev(), expectedTeamCode: await V.teamCode(owner.org) });
  assert.ok(alice.pending);
  await alice.saveItem(alice.personalCid, item('Мой банк'));
  // Заявка не может читать командные коллекции
  const r = await alice.s.read('vault/' + general + '.json').catch(e => e);
  assert.equal(r.status, 403);
  // Обычный участник не создаёт приглашения
  await rejects(alice.s.createInvite(), /Только для владельца/);
});

await test('одобрение и точечный доступ', async () => {
  ads = await owner.createCollection('Реклама', false, []);
  await owner.saveItem(ads, item('Google Ads', 'secret-ads'));
  const pending = await owner.pendingUsers();
  assert.equal(pending[0].code, await alice.myCode());
  await owner.approve(alice.me.uid, pending[0].code, []);
  await alice.refresh();
  await alice.loadAll();
  assert.ok(alice.allItems().some(i => i.name === 'Instagram'));
  const r = await alice.s.read('vault/' + ads + '.json').catch(e => e);
  assert.equal(r.status, 403, 'сервер не отдаёт закрытую коллекцию');
  // Чужой файл участника - только публичная часть
  const other = JSON.parse((await alice.s.read('users/' + owner.me.uid + '.json')).text);
  assert.ok(other.signPk && !other.secret && !other.kdf && !other.authHash);
});

await test('участник не может переписать файл команды', async () => {
  const cur = await alice.s.read(V.ORG);
  const d = JSON.parse(cur.text);
  d.collections[ads].members.push(alice.me.uid);
  d.version += 1;
  d.signer = alice.me.uid;
  delete d.sig;
  d.sig = await C.signObj(alice.me.signSk, d);
  await rejects(alice.s.write(V.ORG, JSON.stringify(d), cur.rev), /Только для владельца/);
});

await test('админ не может подделать владельца, откатить или подписать за другого', async () => {
  await owner.setRole(alice.me.uid, 'admin');
  await alice.refresh();
  const cur = await alice.s.read(V.ORG);
  const base = JSON.parse(cur.text);
  const sign = async d => { d.signer = alice.me.uid; delete d.sig; d.sig = await C.signObj(alice.me.signSk, d); return JSON.stringify(d); };
  // подмена ключа владельца
  const evil = structuredClone(base);
  evil.members[owner.me.uid].boxPk = (await C.generateUserKeys()).boxPk;
  evil.version += 1;
  await rejects(alice.s.write(V.ORG, await sign(evil), cur.rev), /не прошёл проверку/);
  // откат: та же или старая версия
  const old = structuredClone(base);
  await rejects(alice.s.write(V.ORG, await sign(old), cur.rev), /не прошёл проверку/);
  // подпись «за владельца» (signer = owner, подпись Алисы)
  const fake = structuredClone(base);
  fake.version += 1;
  fake.signer = owner.me.uid;
  delete fake.sig;
  fake.sig = await C.signObj(alice.me.signSk, fake);
  await rejects(alice.s.write(V.ORG, JSON.stringify(fake), cur.rev), /не прошёл проверку/);
  await owner.setRole(alice.me.uid, 'member');
  await alice.refresh();
});

await test('подменённое тело запроса при верной подписи не проходит', async () => {
  const s = alice.s;
  const realFetch = s.fetch;
  s.fetch = (url, opts) => realFetch(url, { ...opts, body: opts.body ? opts.body.replace('"seq":', '"seq": ') : opts.body });
  await rejects(alice.saveItem(alice.personalCid, item('X')), /Подпись запроса неверна/);
  s.fetch = realFetch;
});

await test('запись в коллекцию: только с доступом, только текущим ключом, без отката', async () => {
  const cur = await owner.s.read('vault/' + general + '.json');
  const f = JSON.parse(cur.text);
  // Старый файл (seq не больше) - отказ
  const replay = { ...f, signer: owner.me.uid };
  replay.sig = await C.signObj(owner.me.signSk, { t: 'vault', orgId: owner.orgId, cid: general, keyVersion: f.keyVersion, seq: f.seq, data: f.data, signer: owner.me.uid });
  await assert.rejects(owner.s.write('vault/' + general + '.json', JSON.stringify(replay), cur.rev), ConflictError);
  // Алиса без доступа к «Рекламе» не пишет туда даже со своей подписью
  const fa = { v: 1, cid: ads, keyVersion: 1, seq: 999, signer: alice.me.uid, data: f.data };
  fa.sig = await C.signObj(alice.me.signSk, { t: 'vault', orgId: owner.orgId, ...fa, v: undefined });
  await rejects(alice.s.write('vault/' + ads + '.json', JSON.stringify(fa), 1), /Нет доступа/);
  // Чужой личный сейф
  await rejects(alice.s.write('vault/p-' + owner.me.uid + '.json', JSON.stringify({ ...fa, cid: 'p-' + owner.me.uid }), null), /Чужой личный сейф/);
});

await test('удаление участника: доступ пропадает сразу', async () => {
  const s = api();
  s.invite = inviteToken;
  bob = await V.joinTeam(s, { userName: 'Боб', password: 'bob-pass', seen: dev() });
  await owner.approve(bob.me.uid, await bob.myCode(), [ads]);
  await bob.refresh();
  await bob.loadAll();
  await bob.saveItem(ads, item('От Боба'));
  const oldKey = bob.keys.get(ads);
  await owner.removeMember(bob.me.uid);
  await owner.loadAll();
  assert.ok(owner.allItems().some(i => i.name === 'От Боба'), 'записи Боба на месте');
  // Старая сессия Боба: любой подписанный запрос отклоняется
  await rejects(bob.s.read('vault/' + general + '.json'), /Участник удалён/);
  await rejects(bob.saveItem(ads, item('После удаления')), /Участник удалён/);
  await rejects(V.unlock(api(), bob.me.uid, 'bob-pass', dev()), /не найден/);
  // Даже со старым ключом и подписью - сервер не примет (Боба нет в составе)
  assert.ok(oldKey.ver < owner.org.collections[ads].keyVersion);
});

await test('список заявок и удаление файлов - только админам', async () => {
  await rejects(alice.s.list('users'), /Только для владельца/);
  await rejects(alice.s.remove('vault/' + general + '.json'), /Только для владельца/);
  await rejects(owner.s.remove('vault/' + general + '.json'), /ещё используется/);
  await rejects(owner.s.remove(V.ORG), /не удаляется/);
});

await test('смена мастер-пароля через сервер', async () => {
  await alice.changePassword('alice-new-pass');
  await rejects(V.unlock(api(), alice.me.uid, 'alice-pass', dev()), /Неверный/);
  const a = await V.unlock(api(), alice.me.uid, 'alice-new-pass', dev());
  await a.loadAll();
  assert.ok(a.allItems().some(i => i.name === 'Мой банк'));
  // Нельзя под видом смены пароля подменить свои ключи
  const cur = await a.s.read('users/' + a.me.uid + '.json');
  const f = JSON.parse(cur.text);
  f.signPk = (await C.generateUserKeys()).signPk;
  f.authHash = 'x'.repeat(43);
  await rejects(a.s.write('users/' + a.me.uid + '.json', JSON.stringify(f), cur.rev), /только пароль/);
});

await test('в базе сервера нет паролей и ключей в открытом виде', async () => {
  const all = [...db.files.values()].map(f => f.body).join('\n') + JSON.stringify([...db.auth.values()]);
  for (const s of ['secret-ads', 'pw-Instagram', 'Google Ads', 'Мой банк', 'owner-pass', 'Реклама', 'alice-new-pass', 'От Боба']) {
    assert.ok(!all.includes(s), 'нашлось: ' + s);
  }
});

console.log(`\n${passed} тестов прошло${process.exitCode ? ', есть ошибки' : ''}`);
