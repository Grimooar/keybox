// CLI Ключницы для программ-участников (Директор): ядро без process.* - его вызывают kb.mjs и тесты.
//
// Ключи участника - только из переменных окружения (их подставляет хранилище, например vault.py run):
//   KB_API          адрес сервера (по умолчанию - из js/config.js)
//   KB_UID          uid участника
//   KB_SIGN_SK      секретный ключ подписи Ed25519 (pkcs8, base64)
//   KB_BOX_SK       секретный ключ X25519 (pkcs8, base64)
//   KB_TEAM_SECRET  секрет команды из ссылки (#t=...)
//   KB_PIN          закреп команды: <orgId>:<ключ подписи владельца>:<ключ X25519 владельца>
//   KB_STATE_DIR    где хранить версии против отката (по умолчанию ~/.keybox-cli), секретов там нет
//
// Значения секретов CLI не выводит никогда: ни в stdout, ни в stderr, ни в ошибках.
// Пароль или код 2FA получает только дочерний процесс (kb run / kb totp) через переменную окружения.

import { createRequire } from 'node:module';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
globalThis.hashwasm ??= require('../vendor/argon2.umd.min.js');

const C = await import('../js/crypto.js');
const V = await import('../js/vault.js');
const { ApiStorage, ApiError, NetworkError } = await import('../js/storage.js');
const { generatePassword, totpCode } = await import('../js/tools.js');
const { API_URL } = await import('../js/config.js');

// Эти переменные дочернему процессу не передаются: программа, которой нужен один пароль, не получает ключи участника
export const CRED_VARS = ['KB_API', 'KB_UID', 'KB_SIGN_SK', 'KB_BOX_SK', 'KB_TEAM_SECRET', 'KB_PIN', 'KB_MASTER'];
const FIELDS = ['password', 'username', 'totp'];
const SCAN_MAX = 50 * 1024 * 1024;

class UsageError extends Error {}

const HELP = `kb - Ключница для программ (участник-сервис)

  kb enroll --link '<ссылка с #t=..&c=..&i=..>' --name <имя> --out <файл>
        заявка на вступление; ключи - в файл (не на экран), на экран - uid и код для сверки
  kb list [--json]                          записи: имя, id, адрес, логин (без паролей)
  kb create --name N [--url U] [--user L] [--gen 24 | --from-env VAR] [--totp-from-env VAR] [--collection C] [--no-symbols]
  kb run --item N [--field password] --env VAR [--env VAR2=username ...] -- команда [аргументы]
        значение - только в окружение дочернего процесса; код выхода - его
  kb rotate --item N [--gen 24 | --from-env VAR]   новый пароль, старый - в истории записи
  kb totp --item N --env VAR -- команда     код 2FA - только дочернему процессу
  kb selfcheck [--expect 1] [--json]        роль member, флаг сервиса, видна ровно одна коллекция
  kb audit [--after ID] [--since MS] [--limit N]   свои строки журнала сервера (JSON по строке)
  kb scan <файл или папка>...               есть ли значения записей в журналах (печатает только имена записей)`;

// ---------- разбор аргументов ----------

export function parseArgs(argv) {
  const dd = argv.indexOf('--');
  const head = dd < 0 ? argv : argv.slice(0, dd);
  const rest = dd < 0 ? [] : argv.slice(dd + 1);
  const [cmd, ...tail] = head;
  const opts = { _: [] };
  for (let i = 0; i < tail.length; i++) {
    const a = tail[i];
    if (!a.startsWith('--')) { opts._.push(a); continue; }
    const k = a.slice(2);
    const flag = ['json', 'no-symbols', 'help'].includes(k);
    const v = flag ? true : tail[++i];
    if (v === undefined) throw new UsageError('Нет значения для --' + k);
    if (k === 'env') (opts.env ??= []).push(v);
    else opts[k] = v;
  }
  return { cmd, opts, rest };
}

// ---------- ключи и сессия ----------

// Публичные ключи - из секретных (x в jwk - тот же base64url, что b64e), чтобы не хранить их отдельно
async function publicOf(pkcs8B64, alg, usage) {
  const k = await crypto.subtle.importKey('pkcs8', C.b64d(pkcs8B64), { name: alg }, true, usage);
  return (await crypto.subtle.exportKey('jwk', k)).x;
}

export function parsePin(text) {
  const [orgId, ownerSignPk, ownerBoxPk, extra] = String(text || '').split(':');
  if (!/^[0-9a-f]{32}$/.test(orgId || '') || !ownerSignPk || !ownerBoxPk || extra !== undefined) throw new UsageError('KB_PIN: ожидается <orgId>:<ключ подписи владельца>:<ключ X25519 владельца>');
  return { orgId, ownerSignPk, ownerBoxPk };
}

export const pinText = pin => `${pin.orgId}:${pin.ownerSignPk}:${pin.ownerBoxPk}`;

function fileSeen(dir) {
  const path = join(dir, 'seen.json');
  let data = {};
  try { data = JSON.parse(readFileSync(path, 'utf8')); } catch { /* ещё нет */ }
  return {
    get: k => data[k] || null,
    set: (k, v) => {
      data[k] = v;
      mkdirSync(dir, { recursive: true });
      writeFileSync(path, JSON.stringify(data, null, 1));
    },
  };
}

async function session(io) {
  const e = io.env;
  for (const k of ['KB_UID', 'KB_SIGN_SK', 'KB_BOX_SK', 'KB_TEAM_SECRET', 'KB_PIN']) if (!e[k]) throw new UsageError('Нет переменной ' + k + ' (запускайте через хранилище ключей)');
  if (!V.isUid(e.KB_UID)) throw new UsageError('KB_UID: неверный uid');
  const pin = parsePin(e.KB_PIN);
  let me;
  try {
    me = {
      uid: e.KB_UID, name: '',
      boxPk: await publicOf(e.KB_BOX_SK, 'X25519', ['deriveBits']),
      signPk: await publicOf(e.KB_SIGN_SK, 'Ed25519', ['sign']),
      boxSk: await C.importBoxSk(e.KB_BOX_SK),
      signSk: await C.importSignSk(e.KB_SIGN_SK),
      personalKey: new Uint8Array(32), // личного сейфа у сервиса нет
      pin,
      secret: null,
    };
  } catch {
    throw new UsageError('KB_SIGN_SK / KB_BOX_SK: ключ не читается');
  }
  const storage = new ApiStorage(e.KB_API || API_URL, e.KB_TEAM_SECRET, io.fetch);
  const s = new V.Session(storage, me, fileSeen(io.stateDir));
  await s.refresh();
  if (!s.member) throw new V.VaultError('Заявка ещё не принята: участника нет в команде');
  return s;
}

const visible = s => s.collections().filter(c => !c.personal);

async function loadItems(s) {
  await s.loadAll();
  for (const [cid, v] of s.vaults) if (v.error) throw new V.VaultError(`Коллекция «${s.collectionName(cid)}»: ${v.error}`);
  return s.allItems();
}

function findItem(items, ref) {
  if (!ref) throw new UsageError('Нужен --item <имя или id>');
  let found = items.filter(i => i.id === ref);
  if (!found.length) found = items.filter(i => i.name === ref);
  if (!found.length) found = items.filter(i => i.name.toLowerCase() === String(ref).toLowerCase());
  if (!found.length) throw new UsageError('Запись не найдена: ' + ref);
  if (found.length > 1) throw new UsageError('Несколько записей с таким именем, укажите id: ' + found.map(i => i.id).join(', '));
  return found[0];
}

function pickCollection(s, ref) {
  const cols = visible(s);
  if (ref) {
    const c = cols.find(x => x.cid === ref) || cols.find(x => x.name === ref);
    if (!c) throw new UsageError('Коллекция не найдена или нет доступа: ' + ref);
    return c;
  }
  if (cols.length !== 1) throw new UsageError(cols.length ? 'Видно несколько коллекций, укажите --collection' : 'Нет доступных коллекций');
  return cols[0];
}

function newSecret(io, opts) {
  if (opts['from-env']) {
    const v = io.env[opts['from-env']];
    if (!v) throw new UsageError('Пустая переменная ' + opts['from-env']);
    return v;
  }
  const length = opts.gen == null ? 24 : Number(opts.gen);
  if (!Number.isSafeInteger(length) || length < 12 || length > 128) throw new UsageError('--gen: длина от 12 до 128');
  return generatePassword({ length, symbols: !opts['no-symbols'] });
}

// Окружение дочернего процесса: своё окружение без ключей участника + запрошенные значения
function childEnv(io, values) {
  const env = { ...io.env };
  for (const k of CRED_VARS) delete env[k];
  return { ...env, ...values };
}

function envSpecs(opts) {
  const specs = (opts.env || []).map(x => {
    const [name, field] = x.includes('=') ? x.split('=', 2) : [x, opts.field || 'password'];
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new UsageError('Неверное имя переменной: ' + name);
    if (!FIELDS.includes(field)) throw new UsageError('Поле: ' + FIELDS.join(', '));
    if (CRED_VARS.includes(name)) throw new UsageError('Имя ' + name + ' занято ключами Ключницы');
    return { name, field };
  });
  if (!specs.length) throw new UsageError('Нужен --env <ПЕРЕМЕННАЯ>');
  return specs;
}

async function runChild(io, rest, values) {
  if (!rest.length) throw new UsageError('Нужна команда после --');
  return io.spawn(rest[0], rest.slice(1), childEnv(io, values));
}

// ---------- команды ----------

async function cmdEnroll(io, opts) {
  if (!opts.link || !opts.name || !opts.out) throw new UsageError('Нужны --link, --name и --out');
  const hash = String(opts.link).split('#')[1] || '';
  const p = new URLSearchParams(hash);
  const team = p.get('t'), code = (p.get('c') || '').replace(/\D/g, ''), invite = p.get('i');
  if (!team || code.length !== 20 || !invite) throw new UsageError('В ссылке нужны t, c и i: возьмите ссылку-приглашение из приложения');
  if (existsSync(opts.out)) throw new UsageError('Файл ' + opts.out + ' уже есть: не перезаписываю');
  const api = io.env.KB_API || opts.api || API_URL;
  const storage = new ApiStorage(api, team, io.fetch);
  storage.invite = invite;
  const r = await V.readOrg(storage);
  if (!r) throw new V.VaultError('Команда не найдена');
  const teamCode = await V.teamCode(r.org);
  if (teamCode.replace(/\D/g, '') !== code) throw new V.VaultError('Код команды не совпадает со ссылкой: сервер подменил команду или ссылка чужая');
  // Мастер-пароль нужен только для восстановления: случайный, уходит в файл вместе с ключами
  const master = io.env.KB_MASTER || C.b64e(C.randomBytes(24));
  const s = await V.joinTeam(storage, { userName: String(opts.name), password: master, seen: fileSeen(io.stateDir), expectedTeamCode: teamCode, kind: 'service' });
  const creds = {
    KB_API: api, KB_UID: s.me.uid, KB_SIGN_SK: s.me.secret.signSk, KB_BOX_SK: s.me.secret.boxSk,
    KB_TEAM_SECRET: team, KB_PIN: pinText(s.me.pin), KB_MASTER: master,
  };
  writeFileSync(opts.out, JSON.stringify(creds, null, 1) + '\n', { mode: 0o600, flag: 'wx' });
  io.out('Заявка отправлена.');
  io.out('uid: ' + s.me.uid);
  io.out('Код участника (сверить с окном заявки у владельца): ' + await s.myCode());
  io.out('Ключи записаны в ' + opts.out + ' - перенесите их в хранилище ключей и удалите файл.');
  io.out('Владелец: принять заявку с галочкой «Участник-сервис» и добавить в коллекцию.');
  return 0;
}

async function cmdList(io, opts) {
  const s = await session(io);
  const items = await loadItems(s);
  const rows = items.map(i => ({ name: i.name, id: i.id, url: i.uris[0] || '', username: i.username, collection: s.collectionName(i.cid) }))
    .sort((a, b) => a.name.localeCompare(b.name, 'ru'));
  if (opts.json) io.out(JSON.stringify(rows));
  else for (const r of rows) io.out([r.name, r.id, r.url, r.username].join('\t'));
  return 0;
}

async function cmdCreate(io, opts) {
  if (!opts.name) throw new UsageError('Нужно --name');
  const s = await session(io);
  const col = pickCollection(s, opts.collection);
  const items = await loadItems(s);
  if (items.some(i => i.cid === col.cid && i.name === opts.name)) throw new UsageError('Запись «' + opts.name + '» уже есть: для нового пароля - kb rotate');
  const totp = opts['totp-from-env'] ? io.env[opts['totp-from-env']] : '';
  if (opts['totp-from-env'] && !totp) throw new UsageError('Пустая переменная ' + opts['totp-from-env']);
  const it = {
    id: C.randomHex(8), type: 'login', name: String(opts.name), username: String(opts.user || ''),
    password: newSecret(io, opts), uris: opts.url ? [String(opts.url)] : [], totp: totp || '', notes: '', favorite: false,
  };
  const saved = await s.saveItem(col.cid, it);
  io.out('создано: ' + saved.name + '\t' + saved.id);
  return 0;
}

async function cmdRotate(io, opts) {
  const s = await session(io);
  const it = findItem(await loadItems(s), opts.item);
  const { cid, ...rest } = it;
  const saved = await s.saveItem(cid, { ...rest, password: newSecret(io, opts) });
  io.out('пароль сменён: ' + saved.name + '\t' + saved.id);
  return 0;
}

async function cmdRun(io, opts, rest) {
  const specs = envSpecs(opts);
  if (!rest.length) throw new UsageError('Нужна команда после --');
  const s = await session(io);
  const it = findItem(await loadItems(s), opts.item);
  const values = {};
  for (const { name, field } of specs) {
    let v = it[field];
    if (field === 'totp') v = it.totp ? (await totpCode(it.totp, s.s.now())).code : '';
    if (!v) throw new UsageError('У записи «' + it.name + '» пустое поле ' + field);
    values[name] = v;
  }
  return runChild(io, rest, values);
}

async function cmdTotp(io, opts, rest) {
  return cmdRun(io, { ...opts, field: 'totp' }, rest);
}

async function cmdSelfcheck(io, opts) {
  const expect = opts.expect == null ? 1 : Number(opts.expect);
  const s = await session(io);
  const checks = [];
  const check = (ok, what) => checks.push({ ok: !!ok, what });
  check(s.role === 'member', 'роль member (сейчас: ' + s.role + ')');
  check(s.isService, 'флаг участника-сервиса');
  const cols = visible(s);
  check(cols.length === expect, `видно коллекций: ${cols.length}, ожидается ${expect}`);
  check(cols.every(c => !c.all), 'нет коллекций «для всех»');
  // Сервер должен сам не пускать сервис в личный сейф и в отправки
  const personal = await s.s.read('vault/' + V.personalCid(s.me.uid) + '.json').then(() => 200, e => e.status || 0);
  check(personal === 403, 'сервер не отдаёт личный сейф (' + personal + ')');
  // Пустое тело: новый сервер ответит 403 до разбора, старый - 413; отправка не создаётся в любом случае
  const send = (await s.s.req('POST', 'api/sends', '{}')).r.status;
  check(send === 403, 'сервер не даёт создавать отправки (' + send + ')');
  const failed = checks.filter(c => !c.ok).length;
  if (opts.json) io.out(JSON.stringify({ ok: !failed, checks }));
  else {
    for (const c of checks) io.out((c.ok ? 'ok   ' : 'FAIL ') + c.what);
    io.out(failed ? `selfcheck: FAIL (${failed})` : 'selfcheck: ok');
  }
  return failed ? 1 : 0;
}

async function cmdAudit(io, opts) {
  const s = await session(io);
  const n = (k, d) => (opts[k] == null ? d : Number(opts[k]));
  for (const r of await s.s.audit({ after: n('after', 0), since: n('since', 0), limit: n('limit', 200) })) io.out(JSON.stringify(r));
  return 0;
}

function* walk(path) {
  const st = statSync(path);
  if (st.isDirectory()) for (const n of readdirSync(path)) yield* walk(join(path, n));
  else if (st.isFile() && st.size <= SCAN_MAX) yield path;
}

async function cmdScan(io, opts) {
  if (!opts._.length) throw new UsageError('Нужны файлы или папки для проверки');
  const s = await session(io);
  const secrets = [];
  for (const it of await loadItems(s)) {
    for (const v of [it.password, it.totp, ...it.history.map(h => h.password)]) if (v && v.length >= 6) secrets.push({ v, name: it.name });
  }
  let hits = 0;
  for (const root of opts._) {
    for (const f of walk(root)) {
      const text = readFileSync(f, 'utf8');
      const names = new Set(secrets.filter(x => text.includes(x.v)).map(x => x.name));
      for (const name of names) { hits++; io.out('найдено значение записи «' + name + '» в ' + f); }
    }
  }
  io.out(hits ? `scan: найдено ${hits}` : 'scan: чисто');
  return hits ? 1 : 0;
}

const COMMANDS = { enroll: cmdEnroll, list: cmdList, create: cmdCreate, rotate: cmdRotate, run: cmdRun, totp: cmdTotp, selfcheck: cmdSelfcheck, audit: cmdAudit, scan: cmdScan };

// io: { env, fetch, out, err, spawn(cmd, args, env) -> Promise<код>, stateDir }
export async function main(argv, io) {
  io = { stateDir: io.env.KB_STATE_DIR || join(homedir(), '.keybox-cli'), ...io };
  try {
    const { cmd, opts, rest } = parseArgs(argv);
    if (!cmd || cmd === 'help' || opts.help) { io.out(HELP); return cmd ? 0 : 2; }
    const fn = Object.hasOwn(COMMANDS, cmd) ? COMMANDS[cmd] : null;
    if (!fn) throw new UsageError('Неизвестная команда: ' + cmd + ' (kb help)');
    return await fn(io, opts, rest);
  } catch (e) {
    // Только текст ошибки из своих проверок, библиотеки или сервера: значений записей в них нет
    const known = e instanceof UsageError || e instanceof V.VaultError || e instanceof ApiError || e instanceof NetworkError;
    io.err('kb: ' + (known ? e.message : 'внутренняя ошибка (' + (e?.name || 'Error') + ')'));
    return e instanceof UsageError ? 2 : 1;
  }
}
