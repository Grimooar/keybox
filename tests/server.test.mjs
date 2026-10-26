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
  db.attempts.clear(); // снимаем блокировку для остальных тестов
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

// ---------- регрессия по аудиту серверной версии ----------

const loginRaw = (uid, ip) => fetchFn(BASE + '/api/login', { method: 'POST', body: JSON.stringify({ uid, authKey: C.b64e(C.randomBytes(32)) }), headers: { 'X-KB-Team': TEAM, 'CF-Connecting-IP': ip } });
async function signOrg(s, mutate) {
  const cur = await s.s.read(V.ORG);
  const d = JSON.parse(cur.text);
  await mutate(d);
  d.version = (d.version ?? 0) + 1;
  d.signer = s.me.uid;
  delete d.sig;
  d.sig = await C.signObj(s.me.signSk, d);
  return { text: JSON.stringify(d), rev: cur.rev };
}

await test('аудит 3: параллельный подбор не обходит лимит, а владельца с другого адреса не запирает', async () => {
  db.attempts.clear();
  const res = await Promise.all(Array.from({ length: 60 }, () => loginRaw(owner.me.uid, '6.6.6.6')));
  const counts = res.reduce((m, r) => ({ ...m, [r.status]: (m[r.status] || 0) + 1 }), {});
  assert.equal(counts[401], 8, JSON.stringify(counts));
  assert.equal(counts[429], 52);
  const s = await V.unlock(api(), owner.me.uid, 'owner-pass', dev()); // адрес 'local'
  assert.equal(s.role, 'owner');
  db.attempts.clear();
});

await test('аудит 2: «заморозить» коллекцию огромным номером версии нельзя', async () => {
  const cur = await alice.s.read('vault/' + general + '.json');
  const f = JSON.parse(cur.text);
  for (const seq of [1e300, f.seq + 1000, f.seq]) {
    const evil = { ...f, seq, signer: alice.me.uid };
    evil.sig = await C.signObj(alice.me.signSk, { t: 'vault', orgId: owner.orgId, cid: general, keyVersion: f.keyVersion, seq, data: f.data, signer: alice.me.uid });
    await assert.rejects(alice.s.write('vault/' + general + '.json', JSON.stringify(evil), cur.rev), e => e instanceof ConflictError || e.status === 400);
  }
  await owner.saveItem(general, item('После попытки заморозки'));
});

await test('аудит 1: админ не может отрезать владельца от коллекции; испорченный ключ не мешает войти', async () => {
  await owner.setRole(alice.me.uid, 'admin');
  await alice.refresh();
  const drop = await signOrg(alice, d => { delete d.collections[ads].wraps[owner.me.uid]; });
  await rejects(alice.s.write(V.ORG, drop.text, drop.rev), /не прошёл проверку/);
  // Мусор вместо ключа сервер проверить не может - но вход и другие коллекции работают
  const junk = await signOrg(alice, d => { d.collections[ads].wraps[owner.me.uid] = { epk: 'AAAA', iv: 'AAAA', ct: 'AAAA' }; });
  await alice.s.write(V.ORG, junk.text, junk.rev);
  const s = await V.unlock(api(), owner.me.uid, 'owner-pass', dev());
  assert.deepEqual(s.brokenKeys, [ads]);
  await s.loadAll();
  assert.ok(s.allItems().some(i => i.name === 'Instagram'));
  // Владелец возвращает свой ключ: Алиса (у неё ключ есть) перевыдаёт
  const fix = await signOrg(alice, async d => {
    d.collections[ads].wraps[owner.me.uid] = await C.sealTo(owner.me.boxPk, alice.keys.get(ads).key, `wrap:${owner.orgId}:${ads}:${d.collections[ads].keyVersion}:${owner.me.uid}`);
  });
  await alice.s.write(V.ORG, fix.text, fix.rev);
  await owner.refresh();
  assert.ok(owner.keys.has(ads) && !owner.brokenKeys.length);
});

await test('аудит 6: файл команды без номера версии не принимается', async () => {
  const cur = await alice.s.read(V.ORG);
  const d = JSON.parse(cur.text);
  delete d.version;
  d.signer = alice.me.uid;
  delete d.sig;
  d.sig = await C.signObj(alice.me.signSk, d);
  await rejects(alice.s.write(V.ORG, JSON.stringify(d), cur.rev), /не прошёл проверку/);
});

await test('аудит 7: админ не может подменить ключи участника', async () => {
  const s = api();
  s.invite = (await owner.s.createInvite()).token;
  const dan = await V.joinTeam(s, { userName: 'Дэн', password: 'dan-pass-long', seen: dev() });
  await owner.approve(dan.me.uid, await dan.myCode(), []);
  const k = await C.generateUserKeys();
  const evil = await signOrg(alice, d => { d.members[dan.me.uid].signPk = k.signPk; d.members[dan.me.uid].boxPk = k.boxPk; });
  await rejects(alice.s.write(V.ORG, evil.text, evil.rev), /не совпадают с его собственными/);
  await owner.setRole(alice.me.uid, 'member');
  await alice.refresh();
});

await test('аудит 9: лимит приглашения не обходится параллельными заявками', async () => {
  const token = C.b64e(C.randomBytes(24));
  await db.addInvite(await C.sha256b64(token), Date.now() + 60000, 1, owner.me.uid);
  const tries = await Promise.allSettled(Array.from({ length: 5 }, (_, i) => {
    const s = api();
    s.invite = token;
    return V.joinTeam(s, { userName: 'Гонщик ' + i, password: 'racer-pass-' + i, seen: dev() });
  }));
  assert.equal(tries.filter(t => t.status === 'fulfilled').length, 1);
});

await test('аудит 5: сервер не может подсунуть ослабленные параметры Argon2', async () => {
  const sent = [];
  const evilFetch = async (url, opts) => {
    sent.push(url);
    const r = await fetchFn(url, opts);
    if (!url.includes('/api/prelogin/')) return r;
    const d = await r.json();
    return new Response(JSON.stringify({ kdf: { ...d.kdf, m: 16384, t: 1 } }), { status: 200 });
  };
  await rejects(V.unlock(new ApiStorage(BASE, TEAM, evilFetch), owner.me.uid, 'owner-pass', dev()), /Недопустимые параметры/);
  assert.ok(!sent.some(u => u.includes('/api/login')), 'authKey не должен уйти на сервер');
});

await test('аудит 4: новая ссылка команды отключает старую', async () => {
  await rejects(alice.s.rotateTeamSecret(C.b64e(C.randomBytes(24))), /только владелец/);
  const fresh = C.b64e(C.randomBytes(24));
  const ownerApi = api();
  ownerApi.authenticate(owner.me.uid, owner.me.signSk);
  await ownerApi.rotateTeamSecret(fresh);
  await rejects(api(TEAM).people(), /Неверная ссылка/);
  const people = await api(fresh).people();
  assert.ok(people.some(p => p.uid === owner.me.uid));
});

await test('в базе сервера нет паролей и ключей в открытом виде', async () => {
  const all = [...db.files.values()].map(f => f.body).join('\n') + JSON.stringify([...db.auth.values()]);
  for (const s of ['secret-ads', 'pw-Instagram', 'Google Ads', 'Мой банк', 'owner-pass', 'Реклама', 'alice-new-pass', 'От Боба']) {
    assert.ok(!all.includes(s), 'нашлось: ' + s);
  }
});

console.log(`\n${passed} тестов прошло${process.exitCode ? ', есть ошибки' : ''}`);
