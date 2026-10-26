// Сервер Ключницы: хранит только зашифрованные данные одной команды и пропускает запись,
// только если её разрешают те же правила, что проверяет приложение (vault.js):
// подписи владельца/админов, доступ к коллекции, текущая версия ключа, запрет отката.
//
// Заголовки запроса:
//   X-KB-Team   - секрет команды из ссылки (без него сервер не отвечает вовсе)
//   X-KB-Auth   - <uid>:<время>:<подпись Ed25519 запроса> - кто делает запрос
//   X-KB-Invite - токен приглашения (только для заявки на вступление)

import * as C from '../../js/crypto.js';
import { verifyOrg, accessOf, isUid } from '../../js/vault.js';

const ORG = 'org.json';
const MAX_BODY = 2 * 1024 * 1024;
const MAX_USER = 32 * 1024;
const CLOCK_SKEW = 5 * 60 * 1000;
const INVITE_TTL = 7 * 24 * 3600 * 1000;
const INVITE_USES = 25;
// Подбор пароля: с одного адреса - 8 попыток за 15 минут; на участника всего - 50 в час.
// Лимит по адресу не даёт постороннему запереть владельца, общий - ограничивает перебор с многих адресов.
const LIMITS = [
  { key: (uid, ip) => `ip:${uid}:${ip}`, max: 8, window: 15 * 60 * 1000 },
  { key: uid => `uid:${uid}`, max: 50, window: 60 * 60 * 1000 },
];

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, message) => { throw new HttpError(status, message); };

const sha = text => C.sha256b64(text);

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

const vaultPayload = (orgId, f) => ({ t: 'vault', orgId, cid: f.cid, keyVersion: f.keyVersion, seq: f.seq, data: f.data, signer: f.signer });
const selfPayload = (f, orgId) => ({ t: 'user', orgId, uid: f.uid, name: f.name, boxPk: f.boxPk, signPk: f.signPk });
const publicUser = f => ({ v: f.v, uid: f.uid, name: f.name, boxPk: f.boxPk, signPk: f.signPk, selfSig: f.selfSig, createdAt: f.createdAt });

function parseJson(text) {
  try { return JSON.parse(text); } catch { return fail(400, 'Неверный JSON'); }
}

export async function handle(request, db, env) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const cors = {
    'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : allowed[0] || 'null',
    'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-KB-Team, X-KB-Auth, X-KB-Invite',
    'Access-Control-Expose-Headers': 'X-KB-Rev, X-KB-Time',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
  const json = (status, obj, extra = {}) => new Response(JSON.stringify(obj), {
    status, headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-KB-Time': String(Date.now()), ...extra },
  });

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  try {
    const res = await route(request, url, db, env);
    return json(res.status || 200, res.body ?? {}, res.rev != null ? { 'X-KB-Rev': String(res.rev) } : {});
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: e.message });
    console.error(e);
    return json(500, { error: 'Ошибка сервера' });
  }
}

async function readBody(request) {
  if (!['PUT', 'POST'].includes(request.method)) return '';
  if (Number(request.headers.get('Content-Length')) > MAX_BODY) fail(413, 'Слишком большой запрос');
  const body = await request.text();
  if (body.length > MAX_BODY) fail(413, 'Слишком большой запрос');
  return body;
}

async function route(request, url, db, env) {
  const path = url.pathname.replace(/^\/+/, '');
  const method = request.method;
  const body = await readBody(request);

  if (path === 'api/status' && method === 'GET') {
    return { body: { team: !!(await db.meta('pin')) } };
  }
  if (path === 'api/setup' && method === 'POST') return setup(db, env, body);

  // Дальше - только с секретом команды
  const teamHash = await db.meta('team');
  if (!teamHash) fail(404, 'Команда ещё не создана');
  if (!safeEqual(await sha(request.headers.get('X-KB-Team') || ''), teamHash)) fail(403, 'Неверная ссылка команды');

  const pin = JSON.parse(await db.meta('pin'));
  const ctx = { db, pin, orgId: pin.orgId, ip: request.headers.get('CF-Connecting-IP') || 'local' };
  const orgRow = await db.get(ORG);
  ctx.org = JSON.parse(orgRow.body);
  ctx.orgRev = orgRow.rev;

  if (path === 'api/people' && method === 'GET') return people(ctx);
  if (path.startsWith('api/prelogin/') && method === 'GET') return prelogin(ctx, path.slice(13));
  if (path === 'api/login' && method === 'POST') return login(ctx, body);
  if (path === 'api/f/org.json' && method === 'GET') return { body: { text: orgRow.body }, rev: orgRow.rev };
  const join = path.match(/^api\/f\/users\/([0-9a-f]{32})\.json$/);
  if (join && method === 'PUT' && request.headers.get('X-KB-Invite')) {
    return joinRequest(ctx, join[1], body, request.headers.get('X-KB-Invite'));
  }

  // Дальше - только подписанные запросы участников или заявок
  ctx.me = await identify(ctx, request, method, url.pathname + url.search, body);

  if (path === 'api/invites' && method === 'POST') return createInvite(ctx);
  if (path === 'api/team-secret' && method === 'POST') return rotateTeamSecret(ctx, body);
  if (path === 'api/list/users' && method === 'GET') {
    requireAdmin(ctx);
    return { body: { names: (await db.list('users/')).map(p => p.slice(6)) } };
  }

  const m = path.match(/^api\/f\/(org\.json|users\/([0-9a-f]{32})\.json|vault\/((?:p-[0-9a-f]{32})|[0-9a-f]{24})\.json)$/);
  if (!m) fail(404, 'Не найдено');
  const file = m[1];
  const revParam = url.searchParams.get('rev');
  const rev = revParam === 'new' ? null : Number(revParam);
  if (method === 'GET') return readFile(ctx, file, m[2], m[3]);
  if (method === 'PUT') {
    if (rev !== null && !Number.isSafeInteger(rev)) fail(400, 'Неверная версия');
    return writeFile(ctx, file, m[2], m[3], body, rev);
  }
  if (method === 'DELETE') return deleteFile(ctx, file, m[2], m[3]);
  fail(405, 'Метод не поддерживается');
}

// ---------- создание команды (один раз, по коду из настроек сервера) ----------

async function setup(db, env, body) {
  if (await db.meta('pin')) fail(409, 'Команда уже создана');
  const req = parseJson(body);
  if (!env.SETUP_CODE || !safeEqual(String(req.setupCode || ''), env.SETUP_CODE)) fail(403, 'Неверный код установки');
  const org = parseJson(req.org);
  const user = parseJson(req.user);
  const owner = org?.members?.[org?.owner?.uid];
  if (!owner || user.uid !== org.owner.uid || Object.keys(org.members).length !== 1) fail(400, 'Неверные данные команды');
  const pin = { orgId: org.orgId, ownerSignPk: org.owner.signPk, ownerBoxPk: owner.boxPk };
  await verifyOrg(org, pin).catch(() => fail(400, 'Файл команды не прошёл проверку'));
  await checkNewUser(user, user.uid, pin.orgId, req.user);
  if (owner.boxPk !== user.boxPk || owner.signPk !== user.signPk) fail(400, 'Ключи владельца не совпадают');
  if (typeof req.teamHash !== 'string' || req.teamHash.length < 40) fail(400, 'Нет секрета команды');

  const { authHash, ...stored } = user;
  const ok = await db.setupAll({ pin: JSON.stringify(pin), teamHash: req.teamHash, uid: user.uid, userBody: JSON.stringify(stored), authHash, orgBody: req.org });
  if (!ok) fail(409, 'Команда уже создана');
  return { status: 201, body: { ok: true } };
}

async function checkNewUser(f, uid, orgId, raw) {
  if (raw.length > MAX_USER) fail(413, 'Слишком большой файл участника');
  if (!isUid(uid) || f?.uid !== uid || f.v !== 1) fail(400, 'Неверный участник');
  if (typeof f.name !== 'string' || !f.name.trim() || f.name.length > 60) fail(400, 'Неверное имя');
  if (typeof f.authHash !== 'string' || f.authHash.length < 40) fail(400, 'Нет проверки пароля');
  if (!f.secret?.iv || !f.secret?.ct || !f.kdf?.salt) fail(400, 'Нет зашифрованных ключей');
  if (!await C.verifyObj(f.signPk, f.selfSig, selfPayload(f, orgId))) fail(400, 'Подпись участника неверна');
}

// ---------- вход ----------

async function people(ctx) {
  const out = [];
  for (const [uid, m] of Object.entries(ctx.org.members)) out.push({ uid, name: m.name, role: m.role });
  for (const p of await ctx.db.list('users/')) {
    const uid = p.slice(6);
    if (Object.hasOwn(ctx.org.members, uid)) continue;
    const row = await ctx.db.get(p);
    if (row) out.push({ uid, name: JSON.parse(row.body).name, role: 'pending' });
  }
  return { body: { people: out } };
}

async function prelogin(ctx, uid) {
  if (!isUid(uid)) fail(404, 'Участник не найден');
  const row = await ctx.db.get('users/' + uid);
  if (!row) fail(404, 'Участник не найден. Возможно, его удалили из команды.');
  return { body: { kdf: JSON.parse(row.body).kdf } };
}

async function login(ctx, body) {
  const { uid, authKey } = parseJson(body);
  if (!isUid(uid) || typeof authKey !== 'string' || authKey.length > 100) fail(400, 'Неверный запрос');
  const auth = await ctx.db.getAuth(uid);
  const row = await ctx.db.get('users/' + uid);
  if (!auth || !row) fail(404, 'Участник не найден. Возможно, его удалили из команды.');
  // Попытка засчитывается ДО проверки пароля и атомарно - параллельный перебор не обходит лимит
  const now = Date.now();
  for (const l of LIMITS) {
    const a = await ctx.db.attempt(l.key(uid, ctx.ip), now, l.window);
    if (a.fails > l.max) {
      fail(429, 'Слишком много неверных попыток. Подождите ' + Math.max(1, Math.ceil((a.window_start + l.window - now) / 60000)) + ' мин.');
    }
  }
  if (!safeEqual(await sha(authKey), auth.hash)) fail(401, 'Неверный мастер-пароль');
  await ctx.db.clearAttempts(LIMITS[0].key(uid, ctx.ip));
  await ctx.db.forgive(LIMITS[1].key(uid));
  return { body: { text: row.body }, rev: row.rev };
}

// ---------- заявка по приглашению ----------

async function joinRequest(ctx, uid, body, token) {
  const f = parseJson(body);
  await checkNewUser(f, uid, ctx.orgId, body);
  if (Object.hasOwn(ctx.org.members, uid) || await ctx.db.get('users/' + uid)) fail(409, 'Уже есть');
  if (!await ctx.db.useInvite(await sha(token), Date.now())) fail(403, 'Приглашение недействительно или истекло. Попросите новое.');
  const { authHash, ...stored } = f;
  const rev = await ctx.db.put('users/' + uid, JSON.stringify(stored), null);
  if (rev == null) fail(409, 'Уже есть');
  await ctx.db.setAuth(uid, authHash);
  return { status: 201, rev };
}

async function createInvite(ctx) {
  requireAdmin(ctx);
  const token = C.b64e(C.randomBytes(24));
  await ctx.db.addInvite(await sha(token), Date.now() + INVITE_TTL, INVITE_USES, ctx.me.uid);
  return { status: 201, body: { token, expires: Date.now() + INVITE_TTL } };
}

// Новая ссылка команды: старая (например, у удалённого участника) перестаёт работать
async function rotateTeamSecret(ctx, body) {
  if (ctx.me.role !== 'owner') fail(403, 'Менять ссылку команды может только владелец');
  const { teamHash } = parseJson(body);
  if (typeof teamHash !== 'string' || teamHash.length < 40) fail(400, 'Нет секрета команды');
  await ctx.db.setMeta('team', teamHash);
  return { body: { ok: true } };
}

// ---------- подпись запроса ----------

async function identify(ctx, request, method, fullPath, body) {
  const h = request.headers.get('X-KB-Auth') || '';
  const [uid, ts, sig] = h.split(':');
  if (!isUid(uid) || !sig) fail(401, 'Нужен вход');
  if (Math.abs(Date.now() - Number(ts)) > CLOCK_SKEW) fail(401, 'Неверное время на устройстве');
  let pk, role;
  const row = await ctx.db.get('users/' + uid);
  if (!row) fail(401, 'Участник удалён');
  if (Object.hasOwn(ctx.org.members, uid)) {
    pk = ctx.org.members[uid].signPk;
    role = ctx.org.members[uid].role;
  } else {
    pk = JSON.parse(row.body).signPk;
    role = 'pending';
  }
  if (!await C.verifyObj(pk, sig, C.requestPayload(method, fullPath, ts, await sha(body)))) fail(401, 'Подпись запроса неверна');
  return { uid, role, pk };
}

function requireAdmin(ctx) {
  if (!['owner', 'admin'].includes(ctx.me.role)) fail(403, 'Только для владельца и админов');
}

function canReadVault(ctx, cid) {
  if (cid.startsWith('p-')) return cid.slice(2) === ctx.me.uid;
  const col = ctx.org.collections[cid];
  return !!col && ctx.me.role !== 'pending' && accessOf(ctx.org, col).includes(ctx.me.uid);
}

// ---------- файлы ----------

async function readFile(ctx, file, uid, cid) {
  if (file === ORG) return { body: { text: JSON.stringify(ctx.org) }, rev: ctx.orgRev };
  if (uid) {
    const row = await ctx.db.get('users/' + uid);
    if (!row) return { status: 404, body: { error: 'Не найдено' } };
    // Зашифрованные ключи - только самому участнику; остальным - публичная часть (для одобрения заявки)
    if (uid === ctx.me.uid) return { body: { text: row.body }, rev: row.rev };
    if (ctx.me.role === 'pending') fail(403, 'Нет доступа');
    return { body: { text: JSON.stringify(publicUser(JSON.parse(row.body))) }, rev: row.rev };
  }
  if (!canReadVault(ctx, cid)) fail(403, 'Нет доступа к коллекции');
  const row = await ctx.db.get('vault/' + cid);
  if (!row) return { status: 404, body: { error: 'Не найдено' } };
  return { body: { text: row.body }, rev: row.rev };
}

async function writeFile(ctx, file, uid, cid, body, rev) {
  if (file === ORG) return writeOrg(ctx, body, rev);
  if (uid) return writeUser(ctx, uid, body, rev);
  return writeVault(ctx, cid, body, rev);
}

async function cas(ctx, path, body, rev) {
  const newRev = await ctx.db.put(path, body, rev);
  if (newRev == null) fail(409, 'Файл изменился, обновите данные');
  return { rev: newRev };
}

async function writeOrg(ctx, body, rev) {
  requireAdmin(ctx);
  if (rev == null || rev !== ctx.orgRev) fail(409, 'Файл изменился, обновите данные');
  const next = parseJson(body);
  const seen = { get: () => ({ version: ctx.org.version + 1, certVersion: ctx.org.adminCert.certVersion }) };
  await verifyOrg(next, ctx.pin, seen).catch(e => fail(400, 'Файл команды не прошёл проверку: ' + e.message));
  if (next.signer !== ctx.me.uid) fail(400, 'Подписано не вами');
  // Ключи каждого участника - те, что он сам прислал при вступлении (файл участника меняет только он).
  // Так админ не может подставить свой ключ вместо чужого и действовать от имени участника.
  for (const [uid, m] of Object.entries(next.members)) {
    const row = await ctx.db.get('users/' + uid);
    if (!row) fail(400, 'Участник без заявки: ' + m.name);
    const f = JSON.parse(row.body);
    if (f.signPk !== m.signPk || f.boxPk !== m.boxPk) fail(400, 'Ключи участника «' + m.name + '» не совпадают с его собственными');
  }
  return cas(ctx, ORG, body, rev);
}

async function writeUser(ctx, uid, body, rev) {
  // Создание - только по приглашению (выше); здесь - смена мастер-пароля самим участником
  if (uid !== ctx.me.uid) fail(403, 'Можно менять только себя');
  if (body.length > MAX_USER) fail(413, 'Слишком большой файл участника');
  const row = await ctx.db.get('users/' + uid);
  if (!row || rev !== row.rev) fail(409, 'Файл изменился, обновите данные');
  const cur = JSON.parse(row.body);
  const f = parseJson(body);
  for (const k of ['v', 'uid', 'name', 'boxPk', 'signPk', 'selfSig', 'createdAt']) if (f[k] !== cur[k]) fail(400, 'Менять можно только пароль');
  if (typeof f.authHash !== 'string' || f.authHash.length < 40 || !f.secret?.ct || !f.kdf?.salt) fail(400, 'Неверные данные');
  const { authHash, ...stored } = f;
  const res = await cas(ctx, 'users/' + uid, JSON.stringify(stored), rev);
  await ctx.db.setAuth(uid, authHash);
  return res;
}

async function writeVault(ctx, cid, body, rev) {
  const f = parseJson(body);
  if (f.cid !== cid || f.signer !== ctx.me.uid || !Number.isSafeInteger(f.seq) || !Number.isSafeInteger(f.keyVersion)) fail(400, 'Неверный файл коллекции');
  if (cid.startsWith('p-')) {
    if (cid.slice(2) !== ctx.me.uid || f.keyVersion !== 1) fail(403, 'Чужой личный сейф');
  } else {
    if (!canReadVault(ctx, cid)) fail(403, 'Нет доступа к коллекции');
    // Только текущим ключом: бывший участник со старым ключом не запишет ничего
    if (f.keyVersion !== ctx.org.collections[cid].keyVersion) fail(409, 'Ключ коллекции сменился, обновите данные');
  }
  if (!await C.verifyObj(ctx.me.pk, f.sig, vaultPayload(ctx.orgId, f))) fail(400, 'Подпись файла неверна');
  // Номер версии растёт строго на 1: нельзя ни откатить коллекцию, ни «заморозить» её огромным номером
  const row = await ctx.db.get('vault/' + cid);
  const curSeq = row ? JSON.parse(row.body).seq : 0;
  if (f.seq !== curSeq + 1) fail(409, 'Коллекция изменилась, обновите данные');
  if ((row ? row.rev : null) !== rev) fail(409, 'Файл изменился, обновите данные');
  return cas(ctx, 'vault/' + cid, body, rev);
}

async function deleteFile(ctx, file, uid, cid) {
  requireAdmin(ctx);
  if (file === ORG) fail(403, 'Файл команды не удаляется');
  if (uid) {
    if (Object.hasOwn(ctx.org.members, uid)) fail(409, 'Сначала удалите участника из команды');
    await ctx.db.del('users/' + uid);
    await ctx.db.delAuth(uid);
    await ctx.db.del('vault/p-' + uid);
    return { body: { ok: true } };
  }
  if (cid.startsWith('p-') ? Object.hasOwn(ctx.org.members, cid.slice(2)) : Object.hasOwn(ctx.org.collections, cid)) {
    fail(409, 'Коллекция ещё используется');
  }
  await ctx.db.del('vault/' + cid);
  return { body: { ok: true } };
}
