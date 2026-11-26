// Тесты CLI kb: node tests/cli.test.mjs
// CLI говорит с настоящим обработчиком сервера (в памяти); в конце - настоящий процесс kb через http.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
globalThis.hashwasm = require('../vendor/argon2.umd.min.js');

const C = await import('../js/crypto.js');
const { ApiStorage } = await import('../js/storage.js');
const V = await import('../js/vault.js');
const { handle } = await import('../server/src/handler.js');
const { MemoryStore } = await import('../server/src/db.js');
const { main, CRED_VARS, childEnv, winCommand } = await import('../cli/lib.mjs');

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ok  ', name); } catch (e) { console.log('  FAIL', name, '\n      ', e.stack); process.exitCode = 1; }
}

// Всё, что пишут сервер и CLI в консоль, - сюда
const consoleLog = [];
for (const k of ['log', 'warn', 'error', 'info', 'debug']) {
  const orig = console[k];
  console[k] = (...a) => { consoleLog.push(a.map(String).join(' ')); if (k === 'log') orig(...a); };
}

const db = new MemoryStore();
const env = { SETUP_CODE: 'setup-code-cli', ALLOWED_ORIGINS: 'https://grimooar.github.io' };
const fetchFn = (url, opts) => handle(new Request(url, opts), db, env);
const BASE = 'https://api.test';
const TEAM = C.b64e(C.randomBytes(24));
const api = () => new ApiStorage(BASE, TEAM, fetchFn);
const tmp = mkdtempSync(join(tmpdir(), 'kb-cli-'));
const NODE = process.execPath;

// Дочерний процесс: сверяет sha256 переменной с ожидаемым, сам ничего не печатает.
// Ещё проверяет, что ключи участника до него не дошли.
const CHECK = `const h=require('crypto').createHash('sha256').update(process.env[process.argv[1]]||'').digest('hex');
const leaked=${JSON.stringify(CRED_VARS)}.filter(k=>process.env[k]);
process.exit(leaked.length?4:h===process.argv[2]?0:3)`;
const sha = v => require('node:crypto').createHash('sha256').update(v).digest('hex');

const outputs = []; // всё, что CLI вывел (stdout и stderr)
const childOut = [];
const spawnChild = (cmd, args, cenv) => new Promise(resolve => {
  const ch = spawn(cmd, args, { env: cenv, stdio: ['ignore', 'pipe', 'pipe'] });
  ch.stdout.on('data', d => childOut.push(String(d)));
  ch.stderr.on('data', d => childOut.push(String(d)));
  ch.on('exit', c => resolve(c));
});
async function kb(argv, extraEnv = {}) {
  const out = [], err = [];
  const code = await main(argv, {
    env: { ...creds, KB_STATE_DIR: join(tmp, 'state'), ...extraEnv },
    fetch: fetchFn, out: l => out.push(l), err: l => err.push(l), spawn: spawnChild, protectFile: () => true,
  });
  outputs.push(...out, ...err);
  return { code, out: out.join('\n'), err: err.join('\n') };
}

let owner, dirCol, creds = {}, dirUid;
const ownerItems = async () => { await owner.refresh(); await owner.loadAll(); return owner.allItems(); };

await test('enroll: заявка по ссылке-приглашению, ключи - в файл, на экране только uid и код', async () => {
  owner = await V.createTeam(api(), { teamName: 'Студия', userName: 'Владелец', password: 'owner-pass', seen: V.memorySeen(), setup: { setupCode: env.SETUP_CODE, teamHash: await C.sha256b64(TEAM) } });
  const general = owner.collections().find(c => c.all).cid;
  await owner.saveItem(general, { id: C.randomHex(8), type: 'login', name: 'Общий', username: 'x', password: 'general-secret-pw', uris: [], notes: '' });
  const token = (await owner.s.createInvite()).token;
  const code = (await V.teamCode(owner.org)).replace(/\D/g, '');
  const out = join(tmp, 'creds.json');
  // Чужой код команды - отказ
  let r = await kb(['enroll', '--link', `https://app/#t=${TEAM}&c=${'1'.repeat(20)}&i=${token}`, '--name', 'Директор', '--out', out], { KB_API: BASE });
  assert.equal(r.code, 1);
  assert.match(r.err, /Код команды не совпадает/);
  r = await kb(['enroll', '--link', `https://app/#t=${TEAM}&c=${code}&i=${token}`, '--name', 'Директор', '--out', out], { KB_API: BASE });
  assert.equal(r.code, 0, r.err);
  creds = JSON.parse(readFileSync(out, 'utf8'));
  dirUid = creds.KB_UID;
  assert.ok(r.out.includes(dirUid));
  for (const k of ['KB_SIGN_SK', 'KB_BOX_SK', 'KB_TEAM_SECRET', 'KB_MASTER']) assert.ok(!r.out.includes(creds[k]), k + ' на экране');
  // Повторно в тот же файл не пишет
  r = await kb(['enroll', '--link', `https://app/#t=${TEAM}&c=${code}&i=${token}`, '--name', 'Директор', '--out', out], { KB_API: BASE });
  assert.match(r.err, /уже есть/);
  // До приёма заявки работать нельзя
  r = await kb(['list']);
  assert.match(r.err, /не принята/);

  await owner.refresh();
  const p = (await owner.pendingUsers()).find(x => x.uid === dirUid);
  assert.ok(p.service);
  assert.ok(r.code !== 0);
  await owner.updateCollection(general, { all: false, members: [] }); // сервис и «для всех» не совмещаются
  await owner.approve(dirUid, p.code, [], { service: true });
  dirCol = await owner.createCollection('Директор', false, [dirUid]);
});

await test('create: пароль генерирует CLI, на экран - только имя и id', async () => {
  const r = await kb(['create', '--name', 'Хостинг', '--url', 'https://host.example', '--user', 'robot@studio', '--gen', '28']);
  assert.equal(r.code, 0, r.err);
  const it = (await ownerItems()).find(i => i.name === 'Хостинг');
  assert.equal(it.password.length, 28);
  assert.equal(it.cid, dirCol);
  assert.equal(it.updatedBy, dirUid);
  assert.match(r.out, new RegExp('Хостинг\\t' + it.id));
  assert.ok(!r.out.includes(it.password));
  // Второй раз то же имя - нет
  assert.equal((await kb(['create', '--name', 'Хостинг'])).code, 2);
  // Пароль, выданный сайтом, - из переменной окружения
  assert.equal((await kb(['create', '--name', 'API', '--from-env', 'NEW_PW'], { NEW_PW: 'site-given-pw-123' })).code, 0);
  assert.equal((await ownerItems()).find(i => i.name === 'API').password, 'site-given-pw-123');
});

await test('list: имена, id, адреса и логины, без паролей', async () => {
  const r = await kb(['list', '--json']);
  assert.equal(r.code, 0, r.err);
  const rows = JSON.parse(r.out);
  assert.deepEqual(rows.map(x => x.name).sort(), ['API', 'Хостинг']);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['collection', 'id', 'name', 'url', 'username']);
  assert.ok(!r.out.includes('site-given-pw-123') && !r.out.includes('general-secret-pw'));
});

await test('run: значение только в env дочернего процесса, без ключей участника; код выхода - его', async () => {
  const it = (await ownerItems()).find(i => i.name === 'Хостинг');
  let r = await kb(['run', '--item', 'Хостинг', '--env', 'PASS', '--', NODE, '-e', CHECK, 'PASS', sha(it.password)]);
  assert.equal(r.code, 0, r.err);
  r = await kb(['run', '--item', it.id, '--env', 'U=username', '--', NODE, '-e', CHECK, 'U', sha('robot@studio')]);
  assert.equal(r.code, 0);
  r = await kb(['run', '--item', 'Хостинг', '--env', 'PASS', '--', NODE, '-e', CHECK, 'PASS', sha('wrong')]);
  assert.equal(r.code, 3);
  assert.equal((await kb(['run', '--item', 'Нет такой', '--env', 'P', '--', NODE, '-e', '1'])).code, 2);
  assert.equal((await kb(['run', '--item', 'Хостинг', '--env', 'KB_SIGN_SK', '--', NODE, '-e', '1'])).code, 2);
  assert.equal((await kb(['run', '--item', 'Хостинг', '--env', 'P'])).code, 2); // нет команды
});

await test('rotate: новый пароль, старый - в истории', async () => {
  const old = (await ownerItems()).find(i => i.name === 'Хостинг').password;
  const r = await kb(['rotate', '--item', 'Хостинг']);
  assert.equal(r.code, 0, r.err);
  const it = (await ownerItems()).find(i => i.name === 'Хостинг');
  assert.notEqual(it.password, old);
  assert.equal(it.history[0].password, old);
  assert.ok(!r.out.includes(it.password) && !r.out.includes(old));
});

await test('totp: код 2FA только дочернему процессу', async () => {
  const secret = 'JBSWY3DPEHPK3PXP';
  assert.equal((await kb(['create', '--name', 'Почта', '--totp-from-env', 'T'], { T: secret })).code, 0);
  const { totpCode } = await import('../js/tools.js');
  const code = (await totpCode(secret)).code;
  const r = await kb(['totp', '--item', 'Почта', '--env', 'OTP', '--', NODE, '-e', CHECK, 'OTP', sha(code)]);
  assert.equal(r.code, 0, r.err);
  assert.ok(!r.out.includes(code) && !r.out.includes(secret));
});

await test('selfcheck: ok, а при лишней коллекции - FAIL', async () => {
  let r = await kb(['selfcheck']);
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /selfcheck: ok/);
  const extra = await owner.createCollection('Лишняя', false, [dirUid]);
  r = await kb(['selfcheck', '--json']);
  assert.equal(r.code, 1);
  const res = JSON.parse(r.out);
  assert.equal(res.ok, false);
  assert.ok(res.checks.some(c => !c.ok && /коллекций: 2/.test(c.what)));
  // С двумя коллекциями create требует явный выбор
  assert.equal((await kb(['create', '--name', 'X'])).code, 2);
  assert.equal((await kb(['create', '--name', 'X', '--collection', 'Директор'])).code, 0);
  await owner.deleteCollection(extra);
  assert.equal((await kb(['selfcheck'])).code, 0);
});

await test('audit: свои строки журнала сервера', async () => {
  const r = await kb(['audit', '--limit', '1000']);
  assert.equal(r.code, 0, r.err);
  const rows = r.out.split('\n').map(l => JSON.parse(l));
  assert.ok(rows.length > 5 && rows.every(x => x.uid === dirUid));
  assert.ok(rows.some(x => x.route === 'api/f/vault/*' && x.target === dirCol && x.method === 'PUT' && x.status === 200));
});

await test('scan: находит значения записей в журналах, печатает только имена', async () => {
  const it = (await ownerItems()).find(i => i.name === 'Хостинг');
  const logs = join(tmp, 'logs');
  require('node:fs').mkdirSync(logs);
  writeFileSync(join(logs, 'clean.log'), 'ничего секретного\n');
  assert.equal((await kb(['scan', logs])).code, 0);
  writeFileSync(join(logs, 'leak.log'), 'token=' + it.history[0].password + '\n'); // старый пароль из истории тоже ищется
  const r = await kb(['scan', logs]);
  assert.equal(r.code, 1);
  assert.match(r.out, /«Хостинг».*leak\.log/);
  assert.ok(!r.out.includes(it.history[0].password));
  rmSync(join(logs, 'leak.log'));
});

await test('run: ни одной KB_* в любом регистре у дочернего процесса (на Windows регистр не различается)', async () => {
  const env = childEnv({ env: { kb_sign_sk: 'a', Kb_Uid: 'b', KB_OTHER: 'c', KB_SIGN_SK: 'd', PATH: 'p', Home: 'h' } }, { PASS: 'v' });
  assert.deepEqual(env, { PATH: 'p', Home: 'h', PASS: 'v' });
  const NO_KB = "process.exit(Object.keys(process.env).some(k => /^kb_/i.test(k)) ? 4 : 0)";
  const r = await kb(['run', '--item', 'Хостинг', '--env', 'PASS', '--', NODE, '-e', NO_KB], { kb_sign_sk: creds.KB_SIGN_SK, Kb_Team_Secret: creds.KB_TEAM_SECRET });
  assert.equal(r.code, 0, r.err);
  assert.equal((await kb(['run', '--item', 'Хостинг', '--env', 'kb_x', '--', NODE, '-e', '1'])).code, 2);
});

await test('Windows: .cmd/.bat через cmd.exe без shell, аргументы со спецсимволами - отказ', async () => {
  const files = new Set(['C:\\bin\\npm.CMD', 'C:\\bin\\node.EXE', 'C:\\tools\\run.bat']);
  const env = { Path: 'C:\\nope;C:\\bin', PATHEXT: '.COM;.EXE;.BAT;.CMD', ComSpec: 'C:\\Windows\\system32\\cmd.exe' };
  const exists = p => files.has(p);
  // .exe - напрямую
  assert.deepEqual(winCommand('node', ['-v'], { env, exists }), { file: 'C:\\bin\\node.EXE', args: ['-v'] });
  // .cmd по PATH и .bat по пути - через cmd.exe, каждый аргумент в кавычках
  const c = winCommand('npm', ['run', 'build x'], { env, exists });
  assert.equal(c.file, env.ComSpec);
  assert.deepEqual(c.args, ['/d', '/s', '/v:off', '/c', '""C:\\bin\\npm.CMD" "run" "build x""']);
  assert.equal(c.verbatim, true);
  assert.equal(winCommand('C:\\tools\\run.bat', [], { env, exists }).file, env.ComSpec);
  for (const bad of ['a&calc', 'a|b', '%PATH%', 'x"y', 'a>b', 'a^b', 'a!b', 'a\nb']) {
    assert.throws(() => winCommand('npm', [bad], { env, exists }), /спецсимволом/, bad);
  }
  // Не найдено - как есть, ошибку запуска покажет spawn
  assert.deepEqual(winCommand('nothing', [], { env, exists }), { file: 'nothing', args: [] });
});

await test('scan: симлинк на родительскую папку не зацикливает обход', async () => {
  const fs = require('node:fs');
  const root = join(tmp, 'loop');
  fs.mkdirSync(join(root, 'sub'), { recursive: true });
  writeFileSync(join(root, 'sub', 'a.log'), 'ничего\n');
  try { fs.symlinkSync(root, join(root, 'sub', 'up'), 'junction'); } catch { console.log('       (симлинк не создать - проверка пропущена)'); return; }
  const r = await kb(['scan', root]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /scan: чисто/);
});

await test('enroll на Windows: файл закрыт icacls до записи ключей, иначе отказ без заявки', async () => {
  const code = (await V.teamCode(owner.org)).replace(/\D/g, '');
  const run = async (n, io, want = 0) => {
    const err = [];
    const token = (await owner.s.createInvite()).token;
    const r = await main(['enroll', '--link', `https://app/#t=${TEAM}&c=${code}&i=${token}`, '--name', 'Сервис ' + n, '--out', join(tmp, 'win' + n + '.json')],
      { env: { KB_API: BASE, KB_STATE_DIR: join(tmp, 'state-w' + n) }, fetch: fetchFn, out: () => {}, err: l => err.push(l), spawn: spawnChild, ...io });
    assert.equal(r, want, err.join('\n'));
    return err.join('\n');
  };
  // Права ставятся на ещё пустой файл: ключей в нём до icacls нет
  const seen = [];
  assert.match(await run(1, { platform: 'win32', protectFile: p => (seen.push([p, readFileSync(p, 'utf8')]), true) }), /только текущий пользователь/);
  assert.deepEqual(seen, [[join(tmp, 'win1.json'), '']]);
  assert.ok(JSON.parse(readFileSync(join(tmp, 'win1.json'), 'utf8')).KB_SIGN_SK);
  // icacls не сработал - файла нет, заявка не ушла
  await owner.refresh();
  const pending = (await owner.pendingUsers()).length;
  assert.match(await run(2, { platform: 'win32', protectFile: () => { throw new Error('icacls'); } }, 1), /Не удалось ограничить права.*заявка не отправлена/);
  assert.equal(existsSync(join(tmp, 'win2.json')), false);
  await owner.refresh();
  assert.equal((await owner.pendingUsers()).length, pending);
  assert.equal(await run(3, { platform: 'linux' }), '');
});

await test('ошибки: без ключей - подсказка, без значений', async () => {
  const r = await main(['list'], { env: {}, fetch: fetchFn, out: () => {}, err: l => outputs.push(l), spawn: spawnChild });
  assert.equal(r, 2);
  assert.match(outputs.at(-1), /Нет переменной KB_UID/);
  assert.equal(await main(['nope'], { env: {}, fetch: fetchFn, out: () => {}, err: l => outputs.push(l), spawn: spawnChild }), 2);
});

await test('настоящий процесс kb: stdout и stderr без секретов', async () => {
  // http-сервер вокруг того же обработчика
  const srv = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    const r = await fetchFn('http://' + req.headers.host + req.url, { method: req.method, headers: req.headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : body });
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port;
  const run = args => new Promise(resolve => {
    const ch = spawn(NODE, [fileURLToPath(new URL('../cli/kb.mjs', import.meta.url)), ...args], { env: { ...process.env, ...creds, KB_API: url, KB_STATE_DIR: join(tmp, 'state2') }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    ch.stdout.on('data', d => { out += d; });
    ch.stderr.on('data', d => { out += d; });
    ch.on('exit', code => resolve({ code, out }));
  });
  try {
    let r = await run(['create', '--name', 'Процесс', '--collection', 'Директор']);
    assert.equal(r.code, 0, r.out);
    const it = (await ownerItems()).find(i => i.name === 'Процесс');
    r = await run(['run', '--item', 'Процесс', '--env', 'PW', '--', NODE, '-e', CHECK, 'PW', sha(it.password)]);
    assert.equal(r.code, 0, r.out);
    outputs.push(r.out);
    r = await run(['list']);
    assert.equal(r.code, 0, r.out);
    outputs.push(r.out);
    assert.ok(!r.out.includes(it.password));
  } finally { srv.close(); }
});

await test('итог: ни одного секрета в выводе CLI, детей, консоли и журнале сервера', async () => {
  const items = await ownerItems();
  const values = [
    ...items.flatMap(i => [i.password, i.totp, ...i.history.map(h => h.password)]).filter(v => v && v.length >= 6),
    creds.KB_SIGN_SK, creds.KB_BOX_SK, creds.KB_TEAM_SECRET, creds.KB_MASTER, 'owner-pass',
  ];
  assert.ok(values.length >= 8);
  const haystacks = { 'вывод CLI': outputs.join('\n'), 'вывод детей': childOut.join('\n'), 'консоль': consoleLog.join('\n'), 'журнал': JSON.stringify(db.audit) };
  for (const [where, text] of Object.entries(haystacks)) for (const v of values) assert.ok(!text.includes(v), 'секрет в: ' + where);
});

rmSync(tmp, { recursive: true, force: true });
console.log(`\n${passed} тестов прошло${process.exitCode ? ', есть ошибки' : ''}`);
