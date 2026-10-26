// Модель хранилища команды.
//
// Файлы в папке Dropbox (всё, кроме публичных ключей и имён, зашифровано):
//   org.json            - состав команды, коллекции и ключи коллекций, запечатанные
//                         для каждого участника. Подписан владельцем или админом.
//   users/<uid>.json    - участник: публичные ключи + секретные ключи под мастер-паролем.
//   vault/<cid>.json    - записи коллекции, зашифрованы ключом коллекции.
//   vault/p-<uid>.json  - личный сейф участника.
//
// Кому доверять, устройство узнаёт из «закрепа» (pin) - id команды и ключа владельца,
// который хранится внутри зашифрованных данных участника. Подменить org.json
// (добавить себя, выдать себе ключ) без ключа владельца или админа нельзя.

import * as C from './crypto.js';
import { ConflictError } from './storage.js';

export const ORG = 'org.json';
const userPath = uid => `users/${uid}.json`;
const vaultPath = cid => `vault/${cid}.json`;
export const personalCid = uid => 'p-' + uid;

const adWrap = (orgId, cid, ver, uid) => `wrap:${orgId}:${cid}:${ver}:${uid}`;
const adHist = (orgId, cid, ver) => `hist:${orgId}:${cid}:${ver}`;
const adVault = (orgId, cid, ver) => `vault:${orgId}:${cid}:${ver}`;
// Название коллекции зашифровано её же ключом: остальные не видят даже, как она называется
const adName = (orgId, cid, ver) => `name:${orgId}:${cid}:${ver}`;
const adUser = uid => `user:${uid}`;
const selfPayload = (f, orgId) => ({ t: 'user', orgId, uid: f.uid, name: f.name, boxPk: f.boxPk, signPk: f.signPk });
const vaultPayload = (orgId, f) => ({ t: 'vault', orgId, cid: f.cid, keyVersion: f.keyVersion, seq: f.seq, data: f.data, signer: f.signer });

// id участников берутся в том числе из имён файлов - пропускаем только наш формат
export const isUid = uid => typeof uid === 'string' && /^[0-9a-f]{32}$/.test(uid);
function checkUid(uid) {
  if (!isUid(uid)) throw new VaultError('Неверный идентификатор участника');
  return uid;
}

const RETRIES = 6;

export class VaultError extends Error {}
export class RemovedError extends VaultError {}

// Последние виденные версии org.json - защита от отката к старому файлу
export const localSeen = {
  get(orgId) { try { return JSON.parse(localStorage.getItem('kb.seen.' + orgId) || 'null'); } catch { return null; } },
  set(orgId, v) { try { localStorage.setItem('kb.seen.' + orgId, JSON.stringify(v)); } catch { /* приватный режим */ } },
};

export function memorySeen() {
  const m = new Map();
  return { get: k => m.get(k) || null, set: (k, v) => m.set(k, v) };
}

export async function readOrg(storage) {
  const r = await storage.read(ORG);
  return r ? { org: JSON.parse(r.text), rev: r.rev } : null;
}

export function memberCode(uid, m) {
  return C.fingerprint(uid, m.boxPk, m.signPk);
}

// Код команды = код владельца. Новый участник сверяет его с владельцем.
export function teamCode(org) {
  return memberCode(org.owner.uid, org.members[org.owner.uid]);
}

// Владелец подписывает оба ключа каждого админа: тогда другой админ не сможет их подменить
function adminsOf(org) {
  const out = {};
  for (const [uid, m] of Object.entries(org.members)) if (m.role === 'admin') out[uid] = { signPk: m.signPk, boxPk: m.boxPk };
  return out;
}

// Кто получает ключ коллекции: «для всех» - вся команда, иначе выбранные + владелец и админы
export function accessOf(org, col) {
  const uids = Object.keys(org.members);
  if (col.all) return uids;
  return uids.filter(uid => col.members.includes(uid) || org.members[uid].role !== 'member');
}

const fake = () => new VaultError('Файл команды повреждён или подделан. Восстановите прошлую версию org.json в Dropbox.');

export async function verifyOrg(org, pin, seen) {
  if (!org || org.v !== 1 || org.orgId !== pin.orgId) throw fake();
  const owner = org.members?.[org.owner?.uid];
  if (org.owner.signPk !== pin.ownerSignPk || !owner || owner.role !== 'owner' || owner.signPk !== pin.ownerSignPk) throw fake();
  // Ключи владельца не меняются никогда - админ не может «запереть» владельца
  if (owner.boxPk !== pin.ownerBoxPk) throw fake();

  const c = org.adminCert;
  const cert = { orgId: c?.orgId, certVersion: c?.certVersion, admins: c?.admins };
  if (c?.orgId !== org.orgId || !c.admins || typeof c.admins !== 'object' || !await C.verifyObj(pin.ownerSignPk, c.sig, cert)) throw fake();

  const signers = { [org.owner.uid]: pin.ownerSignPk };
  for (const [uid, a] of Object.entries(c.admins)) if (uid !== org.owner.uid) signers[uid] = a.signPk;
  const signerPk = Object.hasOwn(signers, org.signer) ? signers[org.signer] : null;
  const { sig, ...body } = org;
  if (!signerPk || !await C.verifyObj(signerPk, sig, body)) throw fake();

  // Роли в файле должны совпадать с сертификатом админов от владельца
  for (const [uid, m] of Object.entries(org.members)) {
    if (!isUid(uid)) throw fake();
    const certified = Object.hasOwn(c.admins, uid) ? c.admins[uid] : undefined;
    if (m.role === 'admin'
      ? certified?.signPk !== m.signPk || certified?.boxPk !== m.boxPk
      : certified !== undefined) throw fake();
    if (m.role === 'owner' && uid !== org.owner.uid) throw fake();
  }
  for (const uid of Object.keys(c.admins)) if (!Object.hasOwn(org.members, uid)) throw fake();

  const last = seen?.get(org.orgId);
  if (last && (org.version < last.version || c.certVersion < last.certVersion)) {
    throw new VaultError('В Dropbox лежит более старая версия файла команды, чем это устройство уже видело. Похоже на откат или подмену.');
  }
}

async function makeUser({ uid, name, password, pin, keys }) {
  keys = keys || await C.generateUserKeys();
  const kdf = C.newKdf();
  const secret = {
    boxPk: keys.boxPk, signPk: keys.signPk,
    boxSk: keys.boxSk, signSk: keys.signSk,
    personalKey: C.b64e(C.randomBytes(32)),
    pin,
  };
  const file = { v: 1, uid, name, boxPk: keys.boxPk, signPk: keys.signPk, kdf, createdAt: Date.now() };
  const me = await meFromSecret(uid, name, secret);
  file.selfSig = await C.signObj(me.signSk, selfPayload(file, pin.orgId));
  await sealSecret(file, password, secret);
  return { file, me };
}

// Зашифровать ключи участника мастер-паролем. authHash сервер хранит отдельно
// и по нему пускает к файлу - так чужие не могут скачать его и перебирать пароль.
async function sealSecret(file, password, secret) {
  const sub = await C.masterSubkeys(await C.deriveMasterKey(password, file.kdf));
  file.secret = await C.encryptJSON(sub.enc, secret, adUser(file.uid));
  file.authHash = await C.sha256b64(sub.auth);
}

// Вход: на сервере - по проверке пароля, в остальных хранилищах - просто читаем файл
async function loginFile(storage, uid, password) {
  checkUid(uid);
  let kdf, r;
  if (storage.prelogin) {
    kdf = (await storage.prelogin(uid)).kdf;
  } else {
    r = await storage.read(userPath(uid));
    if (!r) throw new VaultError('Участник не найден. Возможно, его удалили из команды.');
    kdf = JSON.parse(r.text).kdf;
  }
  const sub = await C.masterSubkeys(await C.deriveMasterKey(password, kdf));
  if (storage.login) {
    try {
      r = await storage.login(uid, sub.auth);
    } catch (e) {
      if (e.status === 401) throw new VaultError('Неверный мастер-пароль');
      throw e;
    }
  }
  const file = JSON.parse(r.text);
  if (file.uid !== uid) throw new VaultError('Файл участника подменён');
  let secret;
  try {
    secret = await C.decryptJSON(sub.enc, file.secret, adUser(uid));
  } catch {
    throw new VaultError('Неверный мастер-пароль');
  }
  return meFromSecret(uid, file.name, secret);
}

async function meFromSecret(uid, name, secret) {
  return {
    uid, name,
    boxPk: secret.boxPk, signPk: secret.signPk,
    boxSk: await C.importBoxSk(secret.boxSk),
    signSk: await C.importSignSk(secret.signSk),
    personalKey: C.b64d(secret.personalKey),
    pin: secret.pin,
    secret,
  };
}

// ---------- вход ----------

// setup - для сервера: код установки и хэш секрета команды
export async function createTeam(storage, { teamName, userName, password, seen, setup }) {
  if (!setup && await storage.read(ORG)) throw new VaultError('Команда уже создана');
  const orgId = C.randomHex(16);
  const uid = C.randomHex(16);
  const keys = await C.generateUserKeys();
  const { file, me } = await makeUser({ uid, name: userName, password, keys, pin: { orgId, ownerSignPk: keys.signPk, ownerBoxPk: keys.boxPk } });

  const cert = { orgId, certVersion: 1, admins: {} };
  const cid = C.randomHex(12);
  const org = {
    v: 1, orgId, name: teamName, version: 1,
    owner: { uid, signPk: keys.signPk },
    adminCert: { ...cert, sig: await C.signObj(me.signSk, cert) },
    members: { [uid]: { name: userName, role: 'owner', boxPk: keys.boxPk, signPk: keys.signPk, addedAt: Date.now() } },
    collections: { [cid]: { all: true, members: [], keyVersion: 1, wraps: {}, history: null } },
  };
  const key = C.randomBytes(32);
  org.collections[cid].nameBox = await C.encryptJSON(key, 'Общее', adName(orgId, cid, 1));
  org.collections[cid].wraps[uid] = await C.sealTo(keys.boxPk, key, adWrap(orgId, cid, 1, uid));
  org.signer = uid;
  org.sig = await C.signObj(me.signSk, org);

  if (setup) {
    // Сервер создаёт всё одним запросом и сам проверяет подписи
    await storage.setup({ ...setup, user: JSON.stringify(file), org: JSON.stringify(org, null, 1) });
  } else {
    await storage.write(userPath(uid), JSON.stringify(file, null, 1), null);
    try {
      await storage.write(ORG, JSON.stringify(org, null, 1), null);
    } catch (e) {
      await storage.remove(userPath(uid)).catch(() => {});
      if (e instanceof ConflictError) throw new VaultError('Команда уже создана');
      throw e;
    }
  }
  const s = new Session(storage, me, seen);
  await s.refresh();
  return s;
}

// Заявка на вступление: создаём участника, админ подтверждает её у себя
export async function joinTeam(storage, { userName, password, seen, expectedTeamCode }) {
  const r = await readOrg(storage);
  if (!r) throw new VaultError('В этой папке нет команды');
  const pin = { orgId: r.org.orgId, ownerSignPk: r.org.owner?.signPk, ownerBoxPk: r.org.members?.[r.org.owner?.uid]?.boxPk };
  // Пользователь уже сверил этот код с владельцем до вступления (см. экран вступления)
  if (expectedTeamCode && await teamCode(r.org) !== expectedTeamCode) {
    throw new VaultError('Файл команды изменился после проверки кода. Сверьте код команды заново.');
  }
  await verifyOrg(r.org, pin, seen);
  const uid = C.randomHex(16);
  const { file, me } = await makeUser({ uid, name: userName, password, pin });
  await storage.write(userPath(uid), JSON.stringify(file, null, 1), null);
  const s = new Session(storage, me, seen);
  await s.refresh();
  return s;
}

export async function unlock(storage, uid, password, seen) {
  const me = await loginFile(storage, uid, password);
  const s = new Session(storage, me, seen);
  await s.refresh();
  return s;
}

// Список людей для экрана входа (без расшифровки)
export async function listPeople(storage) {
  if (storage.people) return storage.people();
  const r = await readOrg(storage);
  const people = [];
  const seenUids = new Set();
  if (r) {
    for (const [uid, m] of Object.entries(r.org.members || {})) {
      people.push({ uid, name: m.name, role: m.role });
      seenUids.add(uid);
    }
  }
  for (const n of await storage.list('users')) {
    const uid = n.replace(/\.json$/i, '').toLowerCase();
    if (!isUid(uid) || seenUids.has(uid)) continue;
    const f = await storage.read(userPath(uid));
    if (f) people.push({ uid, name: JSON.parse(f.text).name, role: 'pending' });
  }
  return people;
}

const str = v => (typeof v === 'string' ? v : v == null ? '' : String(v));

function normalizeItem(it) {
  const o = it && typeof it === 'object' ? it : {};
  return {
    id: str(o.id),
    type: o.type === 'note' ? 'note' : 'login',
    name: str(o.name) || 'Без названия',
    username: str(o.username),
    password: str(o.password),
    uris: Array.isArray(o.uris) ? o.uris.map(str).filter(Boolean) : [],
    totp: str(o.totp),
    notes: str(o.notes),
    favorite: o.favorite === true,
    history: Array.isArray(o.history) ? o.history.filter(p => p && typeof p === 'object').map(p => ({ password: str(p.password), changedAt: Number(p.changedAt) || 0 })) : [],
    createdAt: Number(o.createdAt) || 0,
    updatedAt: Number(o.updatedAt) || 0,
    updatedBy: str(o.updatedBy),
  };
}

// ---------- сессия ----------

export class Session {
  constructor(storage, me, seen) {
    this.s = storage;
    this.s.authenticate?.(me.uid, me.signSk); // дальше все запросы к серверу подписываются
    this.me = me;
    this.seen = seen;
    this.org = null;
    this.orgRev = null;
    this.keys = new Map();   // cid -> { ver, key, old: { ver: key } }
    this.names = new Map();  // cid -> расшифрованное название
    this.vaults = new Map(); // cid -> { items, rev, error? }
  }

  get orgId() { return this.me.pin.orgId; }
  get member() { return this.org?.members[this.me.uid] || null; }
  get role() { return this.member?.role || 'pending'; }
  get isOwner() { return this.role === 'owner'; }
  get isAdmin() { return this.role === 'owner' || this.role === 'admin'; }
  get pending() { return !this.member; }
  get personalCid() { return personalCid(this.me.uid); }

  async refresh() {
    const r = await readOrg(this.s);
    if (!r) throw new VaultError('Файл команды не найден в папке Dropbox');
    await verifyOrg(r.org, this.me.pin, this.seen);
    const m = Object.hasOwn(r.org.members, this.me.uid) ? r.org.members[this.me.uid] : null;
    if (this.member && !m) throw new RemovedError('Вас удалили из команды. Данные команды больше недоступны.');
    if (m && (m.boxPk !== this.me.boxPk || m.signPk !== this.me.signPk)) {
      throw new VaultError('Ваши ключи в файле команды не совпадают с вашими. Попросите админа заново добавить вас.');
    }
    this.org = r.org;
    this.orgRev = r.rev;
    this.bumpSeen();
    await this.unwrapKeys();
  }

  bumpSeen() {
    const last = this.seen.get(this.orgId) || { version: 0, certVersion: 0 };
    this.seen.set(this.orgId, {
      version: Math.max(last.version, this.org.version),
      certVersion: Math.max(last.certVersion, this.org.adminCert.certVersion),
    });
  }

  async unwrapKeys() {
    const keys = new Map();
    const names = new Map();
    if (this.member) {
      for (const [cid, col] of Object.entries(this.org.collections)) {
        const w = col.wraps[this.me.uid];
        if (!w) continue;
        const key = await C.openSealed(this.me.boxSk, this.me.boxPk, w, adWrap(this.orgId, cid, col.keyVersion, this.me.uid));
        const old = {};
        if (col.history) {
          const h = await C.decryptJSON(key, col.history, adHist(this.orgId, cid, col.keyVersion));
          for (const [v, k] of Object.entries(h)) old[v] = C.b64d(k);
        }
        keys.set(cid, { ver: col.keyVersion, key, old });
        names.set(cid, String(await C.decryptJSON(key, col.nameBox, adName(this.orgId, cid, col.keyVersion))));
      }
    }
    this.keys = keys;
    this.names = names;
  }

  // Коллекции, к которым у меня есть доступ
  collections() {
    const list = [];
    for (const [cid, col] of Object.entries(this.org?.collections || {})) {
      if (this.keys.has(cid)) list.push({ cid, name: this.names.get(cid), all: col.all });
    }
    list.sort((a, b) => (b.all - a.all) || a.name.localeCompare(b.name, 'ru'));
    return [{ cid: this.personalCid, name: 'Личное', personal: true }, ...list];
  }

  collectionName(cid) {
    if (cid === this.personalCid) return 'Личное';
    return this.names.get(cid) || 'Закрытая коллекция';
  }

  currentKey(cid) {
    if (cid === this.personalCid) return { ver: 1, key: this.me.personalKey };
    const k = this.keys.get(cid);
    if (!k) throw new VaultError('Нет доступа к коллекции');
    return k;
  }

  keyFor(cid, ver) {
    const k = this.currentKey(cid);
    if (ver === k.ver) return k.key;
    if (k.old?.[ver]) return k.old[ver];
    throw new VaultError('Ключ коллекции сменился, обновите данные');
  }

  // Кто вправе записывать коллекцию: личную - только я, общую - те, у кого есть к ней доступ
  writerPk(cid, uid, org = this.org) {
    if (cid === this.personalCid) return uid === this.me.uid ? this.me.signPk : null;
    const col = org.collections[cid];
    if (!col || !isUid(uid) || !accessOf(org, col).includes(uid)) return null;
    return org.members[uid].signPk;
  }

  // asOrg - проверять подпись по этому составу команды (нужно при смене ключа после удаления автора)
  async readVault(cid, asOrg = this.org) {
    const seenKey = this.orgId + ':' + cid;
    const last = this.seen.get(seenKey);
    const r = await this.s.read(vaultPath(cid));
    if (!r) {
      // Файла нет, а устройство уже видело записи - значит, его удалили, а не «коллекция пустая»
      if (last?.seq > 0) throw new VaultError('Файл коллекции «' + this.collectionName(cid) + '» пропал из Dropbox. Восстановите его из удалённых файлов Dropbox.');
      return { items: {}, rev: null, seq: 0 };
    }
    const f = JSON.parse(r.text);
    if (f.cid !== cid) throw new VaultError('Файл коллекции подменён');
    // Подпись автора: без неё бывший участник, знающий старый ключ, мог бы подложить свои записи
    const pk = this.writerPk(cid, f.signer, asOrg);
    if (!pk || !Number.isInteger(f.seq) || !await C.verifyObj(pk, f.sig, vaultPayload(this.orgId, f))) {
      throw new VaultError('Файл коллекции «' + this.collectionName(cid) + '» подписан не участником с доступом. Восстановите прошлую версию в Dropbox.');
    }
    if (last && f.seq < last.seq) {
      throw new VaultError('В Dropbox лежит более старая версия коллекции «' + this.collectionName(cid) + '», чем это устройство уже видело.');
    }
    const { items } = await C.decryptJSON(this.keyFor(cid, f.keyVersion), f.data, adVault(this.orgId, cid, f.keyVersion));
    this.bumpVaultSeen(cid, f.seq);
    return { items, rev: r.rev, seq: f.seq };
  }

  bumpVaultSeen(cid, seq) {
    const key = this.orgId + ':' + cid;
    this.seen.set(key, { seq: Math.max(this.seen.get(key)?.seq || 0, seq) });
  }

  async loadAll() {
    const cols = this.collections();
    await Promise.all(cols.map(async c => {
      try {
        this.vaults.set(c.cid, await this.readVault(c.cid));
      } catch (e) {
        this.vaults.set(c.cid, { items: {}, rev: null, error: e.message });
      }
    }));
    for (const cid of [...this.vaults.keys()]) if (!cols.some(c => c.cid === cid)) this.vaults.delete(cid);
  }

  // Записи пишут другие участники - приводим поля к ожидаемым типам, чтобы кривая запись не роняла интерфейс
  allItems() {
    const out = [];
    for (const [cid, v] of this.vaults) for (const item of Object.values(v.items)) out.push({ ...normalizeItem(item), cid });
    return out;
  }

  // Прочитать - изменить - записать; если кто-то успел записать раньше, повторить
  async updateVault(cid, mutate) {
    for (let i = 0; i < RETRIES; i++) {
      let v;
      try {
        v = await this.readVault(cid);
      } catch (e) {
        if (i === 0 && e instanceof VaultError) { await this.refresh(); continue; }
        throw e;
      }
      const res = await mutate(v.items);
      try {
        await this.writeVault(cid, v);
        return res;
      } catch (e) {
        if (!(e instanceof ConflictError)) throw e;
        await this.refresh();
      }
    }
    throw new VaultError('Не удалось сохранить: коллекцию постоянно меняют, попробуйте ещё раз');
  }

  // Записать коллекцию текущим ключом и своей подписью поверх версии v.rev
  async writeVault(cid, v) {
    const { ver, key } = this.currentKey(cid);
    const file = {
      v: 1, cid, keyVersion: ver, seq: v.seq + 1, signer: this.me.uid,
      data: await C.encryptJSON(key, { items: v.items }, adVault(this.orgId, cid, ver)),
    };
    file.sig = await C.signObj(this.me.signSk, vaultPayload(this.orgId, file));
    const rev = await this.s.write(vaultPath(cid), JSON.stringify(file), v.rev);
    this.bumpVaultSeen(cid, file.seq);
    this.vaults.set(cid, { items: v.items, rev, seq: file.seq });
  }

  // ---------- записи ----------

  saveItem(cid, item) {
    const now = Date.now();
    return this.updateVault(cid, items => {
      const prev = items[item.id];
      const next = { ...item, cid: undefined, createdAt: prev?.createdAt || item.createdAt || now, updatedAt: now, updatedBy: this.me.uid };
      delete next.cid;
      next.history = prev?.history || [];
      if (prev?.password && prev.password !== next.password) {
        next.history = [{ password: prev.password, changedAt: now }, ...next.history].slice(0, 10);
      }
      items[item.id] = next;
      return { ...next, cid };
    });
  }

  addItems(cid, list) {
    const now = Date.now();
    return this.updateVault(cid, items => {
      for (const it of list) items[it.id] = { history: [], createdAt: now, ...it, updatedAt: now, updatedBy: this.me.uid };
      return list.length;
    });
  }

  deleteItem(cid, id) {
    return this.updateVault(cid, items => { delete items[id]; });
  }

  async moveItem(item, fromCid, toCid) {
    if (fromCid === toCid) return this.saveItem(toCid, item);
    const saved = await this.saveItem(toCid, item);
    await this.deleteItem(fromCid, item.id);
    return saved;
  }

  // ---------- команда (владелец и админы) ----------

  async updateOrg(mutate) {
    if (!this.isAdmin) throw new VaultError('Менять команду может только владелец или админ');
    for (let i = 0; i < RETRIES; i++) {
      await this.refresh();
      const before = {};
      for (const [cid, col] of Object.entries(this.org.collections)) before[cid] = accessOf(this.org, col);

      const d = structuredClone(this.org);
      const res = await mutate(d);

      // Новые доступы - выдаём ключ; у кого забрали - меняем ключ коллекции
      const rotated = [];
      for (const cid of Object.keys(d.collections)) {
        if (before[cid] && await this.applyAccess(d, cid, before[cid])) rotated.push(cid);
      }

      d.version = this.org.version + 1;
      const admins = adminsOf(d);
      if (C.canonical(admins) !== C.canonical(d.adminCert.admins)) {
        if (!this.isOwner) throw new VaultError('Назначать админов может только владелец');
        const cert = { orgId: d.orgId, certVersion: d.adminCert.certVersion + 1, admins };
        d.adminCert = { ...cert, sig: await C.signObj(this.me.signSk, cert) };
      }
      d.signer = this.me.uid;
      delete d.sig;
      d.sig = await C.signObj(this.me.signSk, d);

      // Записи коллекций со сменой ключа читаем ДО записи нового состава: последним их мог
      // подписать как раз тот, у кого сейчас забирают доступ, и по новому составу подпись не пройдёт.
      const pre = {};
      for (const cid of rotated) {
        try { pre[cid] = await this.readVault(cid); } catch (e) { pre[cid] = null; console.warn(e); }
      }

      try {
        this.orgRev = await this.s.write(ORG, JSON.stringify(d, null, 1), this.orgRev);
      } catch (e) {
        if (e instanceof ConflictError) continue;
        throw e;
      }
      this.org = d;
      this.bumpSeen();
      await this.unwrapKeys();
      // Перешифровать записи новым ключом и переподписать (старый ключ хранится в истории коллекции)
      for (const cid of rotated) {
        if (!pre[cid]) continue; // файл и так был повреждён - оставляем как есть, ошибка видна в интерфейсе
        try {
          await this.writeVault(cid, pre[cid]);
        } catch (e) {
          if (!(e instanceof ConflictError)) throw e;
          await this.updateVault(cid, () => {});
        }
      }
      return res;
    }
    throw new VaultError('Не удалось сохранить: файл команды постоянно меняют, попробуйте ещё раз');
  }

  async wrapFor(d, cid, uid) {
    const col = d.collections[cid];
    const k = this.keys.get(cid);
    if (!k || k.ver !== col.keyVersion) throw new VaultError('Нет актуального ключа коллекции «' + this.collectionName(cid) + '»');
    col.wraps[uid] = await C.sealTo(d.members[uid].boxPk, k.key, adWrap(d.orgId, cid, col.keyVersion, uid));
  }

  // Новый ключ коллекции: название, история старых ключей и выдача всем, у кого есть доступ
  async rekey(d, cid, key, old, name) {
    const col = d.collections[cid];
    col.nameBox = await C.encryptJSON(key, name, adName(d.orgId, cid, col.keyVersion));
    const hist = Object.fromEntries(Object.entries(old).map(([v, k]) => [v, C.b64e(k)]));
    col.history = Object.keys(hist).length ? await C.encryptJSON(key, hist, adHist(d.orgId, cid, col.keyVersion)) : null;
    col.wraps = {};
    for (const uid of accessOf(d, col)) {
      col.wraps[uid] = await C.sealTo(d.members[uid].boxPk, key, adWrap(d.orgId, cid, col.keyVersion, uid));
    }
  }

  async applyAccess(d, cid, before) {
    const col = d.collections[cid];
    const after = accessOf(d, col);
    if (before.some(uid => !after.includes(uid))) {
      const k = this.keys.get(cid);
      if (!k || k.ver !== col.keyVersion) throw new VaultError('Нет актуального ключа коллекции «' + this.collectionName(cid) + '»');
      // Название берём из d: его могли переименовать в этом же изменении
      const name = await C.decryptJSON(k.key, col.nameBox, adName(d.orgId, cid, col.keyVersion));
      col.keyVersion += 1;
      await this.rekey(d, cid, C.randomBytes(32), { ...k.old, [k.ver]: k.key }, name);
      return true;
    }
    for (const uid of after) if (!col.wraps[uid]) await this.wrapFor(d, cid, uid);
    return false;
  }

  async pendingUsers() {
    const out = [];
    for (const n of await this.s.list('users')) {
      const uid = n.replace(/\.json$/i, '').toLowerCase();
      if (!isUid(uid) || Object.hasOwn(this.org.members, uid)) continue;
      const r = await this.s.read(userPath(uid));
      if (!r) continue;
      const f = JSON.parse(r.text);
      const valid = f.uid === uid && await C.verifyObj(f.signPk, f.selfSig, selfPayload(f, this.orgId));
      out.push({ uid, name: f.name, createdAt: f.createdAt, valid, code: valid ? await C.fingerprint(uid, f.boxPk, f.signPk) : null });
    }
    return out;
  }

  // code - проверочный код, который админ сверил с новым участником
  async approve(uid, code, cids = []) {
    const r = await this.s.read(userPath(checkUid(uid)));
    if (!r) throw new VaultError('Заявка не найдена');
    const f = JSON.parse(r.text);
    const valid = f.uid === uid && await C.verifyObj(f.signPk, f.selfSig, selfPayload(f, this.orgId));
    if (!valid || await C.fingerprint(uid, f.boxPk, f.signPk) !== code) {
      throw new VaultError('Заявка изменилась после проверки кода. Сверьте код заново.');
    }
    await this.updateOrg(d => {
      d.members[uid] = { name: f.name, role: 'member', boxPk: f.boxPk, signPk: f.signPk, addedAt: Date.now() };
      for (const cid of cids) {
        const col = d.collections[cid];
        if (col && !col.all && !col.members.includes(uid)) col.members.push(uid);
      }
    });
  }

  async reject(uid) {
    checkUid(uid);
    if (Object.hasOwn(this.org.members, uid)) throw new VaultError('Это уже участник команды');
    if (!this.isAdmin) throw new VaultError('Отклонять заявки может только владелец или админ');
    await this.s.remove(userPath(uid));
  }

  async removeMember(uid) {
    checkUid(uid);
    const m = this.org.members[uid];
    if (!m) return;
    if (m.role === 'owner') throw new VaultError('Владельца удалить нельзя');
    if (uid === this.me.uid) throw new VaultError('Себя удалить нельзя');
    if (m.role === 'admin' && !this.isOwner) throw new VaultError('Админа может удалить только владелец');
    await this.updateOrg(d => {
      delete d.members[uid];
      for (const col of Object.values(d.collections)) col.members = col.members.filter(u => u !== uid);
    });
    await this.s.remove(userPath(uid));
    await this.s.remove(vaultPath(personalCid(uid)));
  }

  async setRole(uid, role) {
    if (!this.isOwner) throw new VaultError('Менять роли может только владелец');
    if (!['admin', 'member'].includes(role)) throw new VaultError('Неизвестная роль');
    checkUid(uid);
    if (!Object.hasOwn(this.org.members, uid)) throw new VaultError('Участник не найден');
    if (this.org.members[uid].role === 'owner') throw new VaultError('Роль владельца не меняется');
    await this.updateOrg(d => { d.members[uid].role = role; });
  }

  async createCollection(name, all, members = []) {
    const cid = C.randomHex(12);
    await this.updateOrg(async d => {
      d.collections[cid] = { all: !!all, members: all ? [] : members.filter(u => isUid(u) && Object.hasOwn(d.members, u)), keyVersion: 1, wraps: {}, history: null };
      await this.rekey(d, cid, C.randomBytes(32), {}, String(name));
    });
    return cid;
  }

  updateCollection(cid, { name, all, members }) {
    return this.updateOrg(async d => {
      const col = Object.hasOwn(d.collections, cid) ? d.collections[cid] : null;
      if (!col) throw new VaultError('Коллекция не найдена');
      if (name != null) {
        const k = this.currentKey(cid);
        col.nameBox = await C.encryptJSON(k.key, String(name), adName(d.orgId, cid, col.keyVersion));
      }
      if (all != null) col.all = !!all;
      if (members) col.members = col.all ? [] : members.filter(u => isUid(u) && Object.hasOwn(d.members, u));
    });
  }

  async deleteCollection(cid) {
    await this.updateOrg(d => { delete d.collections[cid]; });
    await this.s.remove(vaultPath(cid));
    this.vaults.delete(cid);
  }

  // ---------- мои настройки ----------

  async checkPassword(password) {
    await loginFile(this.s, this.me.uid, password);
  }

  async changePassword(newPassword) {
    for (let i = 0; i < RETRIES; i++) {
      const r = await this.s.read(userPath(this.me.uid));
      const f = JSON.parse(r.text);
      f.kdf = C.newKdf();
      await sealSecret(f, newPassword, this.me.secret);
      try {
        await this.s.write(userPath(this.me.uid), JSON.stringify(f, null, 1), r.rev);
        return;
      } catch (e) {
        if (!(e instanceof ConflictError)) throw e;
      }
    }
  }

  myCode() { return C.fingerprint(this.me.uid, this.me.boxPk, this.me.signPk); }
}
