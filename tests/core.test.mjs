// Тесты ядра: node tests/core.test.mjs
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
globalThis.hashwasm = require('../vendor/argon2.umd.min.js');

const C = await import('../js/crypto.js');
const { MemoryStorage } = await import('../js/storage.js');
const V = await import('../js/vault.js');

let passed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  ok  ', name);
  } catch (e) {
    console.log('  FAIL', name, '\n      ', e.stack);
    process.exitCode = 1;
  }
}

const rejects = async (p, re) => assert.rejects(p, e => (re.test(e.message) ? true : assert.fail('ошибка: ' + e.message)));
const item = (name, password = 'pw-' + name) => ({ id: C.randomHex(8), type: 'login', name, username: 'u', password, uris: [], notes: '' });

const st = new MemoryStorage();
const dev = () => V.memorySeen(); // у каждого «устройства» своя память версий

let owner, alice, bob, general, ads;

await test('крипто: шифрование, запечатывание, подпись', async () => {
  const k = C.randomBytes(32);
  const box = await C.encryptJSON(k, { a: 1 }, 'ad');
  assert.deepEqual(await C.decryptJSON(k, box, 'ad'), { a: 1 });
  await assert.rejects(C.decryptJSON(k, box, 'other-ad'));
  const keys = await C.generateUserKeys();
  const sealed = await C.sealTo(keys.boxPk, new Uint8Array([1, 2, 3]), 'x');
  assert.deepEqual([...await C.openSealed(await C.importBoxSk(keys.boxSk), keys.boxPk, sealed, 'x')], [1, 2, 3]);
  const sig = await C.signObj(await C.importSignSk(keys.signSk), { b: 2, a: 1 });
  assert.ok(await C.verifyObj(keys.signPk, sig, { a: 1, b: 2 }));
  assert.ok(!await C.verifyObj(keys.signPk, sig, { a: 1, b: 3 }));
});

await test('владелец создаёт команду с коллекцией «Общее»', async () => {
  owner = await V.createTeam(st, { teamName: 'Студия', userName: 'Владелец', password: 'owner-pass', seen: dev() });
  assert.equal(owner.role, 'owner');
  const cols = owner.collections();
  assert.equal(cols[0].personal, true);
  general = cols.find(c => c.all).cid;
  await owner.saveItem(general, item('Instagram'));
  await owner.saveItem(owner.personalCid, item('Личная почта'));
  await rejects(V.createTeam(st, { teamName: 'X', userName: 'Y', password: 'z', seen: dev() }), /Команда уже создана/);
});

await test('неверный мастер-пароль не пускает', async () => {
  await rejects(V.unlock(st, owner.me.uid, 'wrong', dev()), /Неверный мастер-пароль/);
});

await test('заявка: до одобрения есть только личный сейф', async () => {
  alice = await V.joinTeam(st, { userName: 'Алиса', password: 'alice-pass', seen: dev() });
  assert.ok(alice.pending);
  assert.equal(alice.collections().length, 1);
  await alice.saveItem(alice.personalCid, item('Мой банк'));
  await alice.loadAll();
  assert.equal(alice.allItems().length, 1);
});

await test('админ видит заявку с тем же кодом и одобряет', async () => {
  ads = await owner.createCollection('Реклама', false, []);
  await owner.saveItem(ads, item('Google Ads', 'secret-ads'));
  const pending = await owner.pendingUsers();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].code, await alice.myCode());
  await rejects(owner.approve(alice.me.uid, '0000 0000 0000 0000 0000', []), /Сверьте код/);
  await owner.approve(alice.me.uid, pending[0].code, []);
  await alice.refresh();
  await alice.loadAll();
  const names = alice.allItems().map(i => i.name).sort();
  assert.deepEqual(names, ['Instagram', 'Мой банк']);
  assert.ok(!alice.collections().some(c => c.cid === ads), 'Алиса не должна видеть «Рекламу»');
});

await test('точечный доступ: Боб получает «Рекламу»', async () => {
  bob = await V.joinTeam(st, { userName: 'Боб', password: 'bob-pass', seen: dev() });
  await owner.approve(bob.me.uid, await bob.myCode(), [ads]);
  await bob.refresh();
  await bob.loadAll();
  assert.ok(bob.allItems().some(i => i.name === 'Google Ads'));
  // Вход с нового устройства
  const bob2 = await V.unlock(st, bob.me.uid, 'bob-pass', dev());
  await bob2.loadAll();
  assert.equal(bob2.allItems().length, bob.allItems().length);
});

await test('участник не может подделать файл команды', async () => {
  const orig = await st.read(V.ORG);
  const forged = JSON.parse(orig.text);
  forged.collections[ads].members.push(alice.me.uid);
  forged.version += 1;
  forged.signer = alice.me.uid;
  delete forged.sig;
  forged.sig = await C.signObj(alice.me.signSk, forged);
  await st.write(V.ORG, JSON.stringify(forged), orig.rev);
  await rejects(owner.refresh(), /подделан/);
  await rejects(bob.refresh(), /подделан/);
  // Назначить себя админом тоже не выйдет
  forged.members[alice.me.uid].role = 'admin';
  const cur = await st.read(V.ORG);
  await st.write(V.ORG, JSON.stringify(forged), cur.rev);
  await rejects(alice.refresh(), /подделан/);
  const back = await st.read(V.ORG);
  await st.write(V.ORG, orig.text, back.rev);
  await owner.refresh();
});

await test('откат к старой версии файла команды замечается', async () => {
  const old = await st.read(V.ORG);
  await owner.saveItem(general, item('Telegram'));
  await owner.createCollection('Временная', false, []);
  const cur = await st.read(V.ORG);
  await st.write(V.ORG, old.text, cur.rev);
  await rejects(owner.refresh(), /более старая версия/);
  const now = await st.read(V.ORG);
  await st.write(V.ORG, cur.text, now.rev);
  await owner.refresh();
});

await test('одновременная запись с двух устройств - ничего не теряется', async () => {
  const a2 = await V.unlock(st, alice.me.uid, 'alice-pass', dev());
  await Promise.all([
    alice.saveItem(general, item('Параллельно-1')),
    a2.saveItem(general, item('Параллельно-2')),
    owner.saveItem(general, item('Параллельно-3')),
  ]);
  await owner.loadAll();
  const names = owner.allItems().map(i => i.name);
  for (const n of ['Параллельно-1', 'Параллельно-2', 'Параллельно-3', 'Instagram', 'Telegram']) assert.ok(names.includes(n), n);
});

await test('история пароля сохраняется при изменении', async () => {
  const it = item('Почта', 'old-1');
  await owner.saveItem(general, it);
  const saved = await owner.saveItem(general, { ...it, password: 'new-2' });
  assert.equal(saved.history[0].password, 'old-1');
});

await test('удаление участника: ключ коллекции меняется, старым ключом не открыть', async () => {
  const bobOldKey = bob.keys.get(ads);
  await owner.removeMember(bob.me.uid);
  const col = owner.org.collections[ads];
  assert.equal(col.keyVersion, bobOldKey.ver + 1);
  assert.ok(!col.wraps[bob.me.uid]);
  const f = JSON.parse((await st.read('vault/' + ads + '.json')).text);
  assert.equal(f.keyVersion, col.keyVersion);
  await assert.rejects(C.decryptJSON(bobOldKey.key, f.data, `vault:${owner.orgId}:${ads}:${f.keyVersion}`));
  // Записи на месте и читаются новым ключом
  await owner.loadAll();
  assert.ok(owner.allItems().some(i => i.name === 'Google Ads'));
  await rejects(bob.refresh(), /Вас удалили из команды/);
  await rejects(V.unlock(st, bob.me.uid, 'bob-pass', dev()), /не найден/);
});

await test('роли: админ получает все коллекции, после понижения ключ меняется', async () => {
  await rejects(alice.setRole(alice.me.uid, 'admin'), /только владелец/);
  await owner.setRole(alice.me.uid, 'admin');
  await alice.refresh();
  assert.ok(alice.isAdmin);
  assert.ok(alice.keys.has(ads));
  // Админ может принимать новых участников
  const carl = await V.joinTeam(st, { userName: 'Карл', password: 'carl-pass', seen: dev() });
  await alice.approve(carl.me.uid, await carl.myCode(), []);
  await owner.refresh();
  assert.ok(owner.org.members[carl.me.uid]);
  await rejects(alice.setRole(carl.me.uid, 'admin'), /только владелец/);
  const ver = owner.org.collections[ads].keyVersion;
  await owner.setRole(alice.me.uid, 'member');
  assert.equal(owner.org.collections[ads].keyVersion, ver + 1);
  await alice.refresh();
  assert.ok(!alice.keys.has(ads));
  await rejects(alice.createCollection('X', true), /владелец или админ/);
});

await test('изменение состава коллекции и удаление коллекции', async () => {
  await owner.updateCollection(ads, { members: [alice.me.uid] });
  await alice.refresh();
  assert.ok(alice.keys.has(ads));
  await alice.loadAll();
  assert.ok(alice.allItems().some(i => i.name === 'Google Ads'));
  const ver = owner.org.collections[ads].keyVersion;
  await owner.updateCollection(ads, { members: [] });
  assert.equal(owner.org.collections[ads].keyVersion, ver + 1);
  const tmp = [...owner.names].find(([, n]) => n === 'Временная')[0];
  await owner.deleteCollection(tmp);
  assert.ok(!owner.org.collections[tmp]);
});

await test('смена мастер-пароля', async () => {
  await alice.changePassword('alice-new');
  await rejects(V.unlock(st, alice.me.uid, 'alice-pass', dev()), /Неверный/);
  const a = await V.unlock(st, alice.me.uid, 'alice-new', dev());
  await a.loadAll();
  assert.ok(a.allItems().some(i => i.name === 'Мой банк'));
});

await test('перенос записи между коллекциями', async () => {
  const it = item('Переносимая');
  await owner.saveItem(owner.personalCid, it);
  await owner.moveItem(it, owner.personalCid, general);
  await owner.loadAll();
  const found = owner.allItems().filter(i => i.id === it.id);
  assert.equal(found.length, 1);
  assert.equal(found[0].cid, general);
});

await test('бывший участник со старым ключом не может подложить записи', async () => {
  // Выдаём Карлу доступ к «Рекламе», запоминаем ключ и удаляем его
  const carlUid = Object.entries(owner.org.members).find(([, m]) => m.name === 'Карл')[0];
  await owner.updateCollection(ads, { members: [carlUid] });
  const carlKey = owner.keys.get(ads);
  await owner.removeMember(carlUid);
  const path = 'vault/' + ads + '.json';
  const cur = await st.read(path);
  const f = JSON.parse(cur.text);
  const evil = item('Фишинг', 'stolen');
  const forged = { ...f, keyVersion: carlKey.ver, seq: f.seq + 1, signer: carlUid,
    data: await C.encryptJSON(carlKey.key, { items: { [evil.id]: evil } }, `vault:${owner.orgId}:${ads}:${carlKey.ver}`) };
  forged.sig = 'AAAA';
  await st.write(path, JSON.stringify(forged), cur.rev);
  await rejects(owner.readVault(ads), /подписан не участником/);
  // Подпись Алисы (у неё нет доступа к «Рекламе») тоже не годится
  forged.signer = alice.me.uid;
  forged.sig = await C.signObj(alice.me.signSk, { t: 'vault', orgId: owner.orgId, cid: ads, keyVersion: forged.keyVersion, seq: forged.seq, data: forged.data, signer: alice.me.uid });
  const cur2 = await st.read(path);
  await st.write(path, JSON.stringify(forged), cur2.rev);
  await rejects(owner.readVault(ads), /подписан не участником/);
  const cur3 = await st.read(path);
  await st.write(path, cur.text, cur3.rev);
  assert.ok(Object.values((await owner.readVault(ads)).items).some(i => i.name === 'Google Ads'));
});

await test('откат файла коллекции к старой версии замечается', async () => {
  const path = 'vault/' + general + '.json';
  const old = await st.read(path);
  await owner.saveItem(general, item('Новая'));
  const cur = await st.read(path);
  await st.write(path, old.text, cur.rev);
  await rejects(owner.readVault(general), /более старая версия коллекции/);
  const now = await st.read(path);
  await st.write(path, cur.text, now.rev);
});

await test('id вида __proto__ в имени файла заявки игнорируется', async () => {
  await st.write('users/__proto__.json', '{"uid":"__proto__","name":"x"}', null);
  const pending = await owner.pendingUsers();
  assert.ok(!pending.some(p => p.uid === '__proto__'));
  await rejects(owner.approve('__proto__', 'x', []), /идентификатор/);
  await st.remove('users/__proto__.json');
});

await test('TOTP совпадает с эталоном RFC 6238', async () => {
  const T = await import('../js/tools.js');
  // секрет "12345678901234567890" в base32, время 59 с -> 287082
  const r = await T.totpCode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000);
  assert.equal(r.code, '287082');
  assert.equal(T.safeUrl('javascript:alert(1)'), null);
  assert.equal(T.safeUrl('example.com'), 'https://example.com/');
  const pw = T.generatePassword({ length: 32 });
  assert.equal(pw.length, 32);
  assert.ok(/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw));
  const items = T.importCsv('name,url,username,password\nСайт,https://a.ru,"vova, admin","p""w"\n');
  assert.equal(items[0].username, 'vova, admin');
  assert.equal(items[0].password, 'p"w');
});

// ---------- регрессия по аудиту ----------

await test('аудит P1: удаление участника, который последним записал коллекцию', async () => {
  const dan = await V.joinTeam(st, { userName: 'Дэн', password: 'dan-pass', seen: dev() });
  await owner.approve(dan.me.uid, await dan.myCode(), [ads]);
  await dan.refresh();
  await dan.saveItem(general, item('От Дэна в общем'));
  await dan.saveItem(ads, item('От Дэна в рекламе'));
  await owner.removeMember(dan.me.uid);
  await owner.loadAll();
  for (const cid of [general, ads]) assert.ok(!owner.vaults.get(cid).error, owner.vaults.get(cid).error);
  const names = owner.allItems().map(i => i.name);
  assert.ok(names.includes('От Дэна в общем') && names.includes('От Дэна в рекламе'));
  await owner.saveItem(general, item('После Дэна'));
  assert.equal(await st.read('users/' + dan.me.uid + '.json'), null, 'файл участника удалён');
  // Алиса (другое устройство) тоже читает
  await alice.refresh();
  await alice.loadAll();
  assert.ok(!alice.vaults.get(general).error);
});

await test('аудит P2: удалённый файл коллекции не выглядит пустой коллекцией', async () => {
  const path = 'vault/' + general + '.json';
  const saved = await st.read(path);
  await st.remove(path);
  await rejects(owner.readVault(general), /пропал с сервера/);
  await rejects(owner.saveItem(general, item('X')), /пропал с сервера/);
  await st.write(path, saved.text, null);
  await owner.readVault(general);
});

await test('аудит P3: админ не может подменить ключи владельца или другого админа', async () => {
  await owner.setRole(alice.me.uid, 'admin');
  await alice.refresh();
  const carol = await V.joinTeam(st, { userName: 'Кэрол', password: 'carol-pass', seen: dev() });
  await owner.approve(carol.me.uid, await carol.myCode(), []);
  await owner.setRole(carol.me.uid, 'admin');
  const evilKeys = await C.generateUserKeys();
  for (const target of [owner.me.uid, carol.me.uid]) {
    const orig = await st.read(V.ORG);
    const d = JSON.parse(orig.text);
    d.members[target].boxPk = evilKeys.boxPk;
    d.version += 1;
    d.signer = alice.me.uid;
    delete d.sig;
    d.sig = await C.signObj(alice.me.signSk, d);
    await st.write(V.ORG, JSON.stringify(d), orig.rev);
    await rejects(V.unlock(st, owner.me.uid, 'owner-pass', dev()), /подделан/);
    await rejects(bob2Check(), /подделан/);
    const cur = await st.read(V.ORG);
    await st.write(V.ORG, orig.text, cur.rev);
  }
  async function bob2Check() { const s = await V.unlock(st, carol.me.uid, 'carol-pass', dev()); return s; }
  await owner.refresh();
  await owner.setRole(alice.me.uid, 'member');
});

await test('аудит п.6: вступление проверяет код команды, сверенный заранее', async () => {
  const r = await V.readOrg(st);
  const code = await V.teamCode(r.org);
  await rejects(V.joinTeam(st, { userName: 'Ева', password: 'eve-pass', seen: dev(), expectedTeamCode: '1111 2222 3333 4444 5555' }), /Сверьте код команды/);
  const eve = await V.joinTeam(st, { userName: 'Ева', password: 'eve-pass', seen: dev(), expectedTeamCode: code });
  await owner.reject(eve.me.uid);
});

await test('аудит п.7: названия коллекций не лежат открытым текстом', async () => {
  const text = (await st.read(V.ORG)).text;
  for (const n of ['Общее', 'Реклама']) assert.ok(!text.includes(n), 'нашлось название: ' + n);
  await alice.refresh();
  assert.ok(!alice.collections().some(c => c.cid === ads));
  assert.equal(alice.collectionName(ads), 'Закрытая коллекция');
  await owner.updateCollection(ads, { name: 'Реклама 2' });
  assert.equal(owner.collectionName(ads), 'Реклама 2');
  // Переименование вместе со сменой ключа
  await owner.updateCollection(ads, { name: 'Реклама', members: [alice.me.uid] });
  await owner.updateCollection(ads, { name: 'Реклама 3', members: [] });
  assert.equal(owner.collectionName(ads), 'Реклама 3');
});

await test('аудит: параметры Argon2 и кривые записи не роняют приложение', async () => {
  await assert.rejects(C.deriveMasterKey('x', { alg: 'argon2id', salt: 'AAAA', m: 1048576, t: 20, p: 1 }), /Недопустимые/);
  owner.vaults.set('bad', { items: { a: { name: 5, uris: 'x', history: [null, 3] }, b: null } });
  const bad = owner.allItems().filter(i => i.cid === 'bad');
  assert.equal(bad.length, 2);
  assert.ok(bad.every(i => typeof i.name === 'string' && Array.isArray(i.uris) && Array.isArray(i.history)));
  owner.vaults.delete('bad');
  const T = await import('../js/tools.js');
  await assert.rejects(T.totpCode('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=1000'), /Неподдерживаемые/);
  for (const p of ['Summer2024!!', 'Admin2024Admin', 'Password1234', 'GearPoint2025!']) assert.ok(T.strength(p).level < 3, p);
  assert.ok(T.strength('correct horse battery staple').level >= 3);
});

await test('в файлах Dropbox нет ни одного пароля открытым текстом', async () => {
  const all = [...st.files.values()].map(f => f.text).join('\n');
  for (const s of ['secret-ads', 'pw-Instagram', 'new-2', 'Google Ads', 'Мой банк', 'owner-pass', 'Реклама']) {
    assert.ok(!all.includes(s), 'нашёлся текст: ' + s);
  }
});

console.log(`\n${passed} тестов прошло${process.exitCode ? ', есть ошибки' : ''}`);
