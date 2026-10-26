// Криптография Ключницы.
// Argon2id (hash-wasm) - ключ из мастер-пароля.
// WebCrypto: AES-256-GCM - шифрование, X25519 + HKDF - передача ключей участникам,
// Ed25519 - подписи файла команды. Свои шифры не пишем, только стандартные примитивы.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export const KDF_DEFAULT = { alg: 'argon2id', m: 65536, t: 3, p: 1 }; // 64 МБ, 3 прохода

export class CryptoError extends Error {}

// ---------- байты и кодировки ----------

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// Hex, а не base64: пути в Dropbox не различают регистр букв
export function randomHex(n = 16) {
  return [...randomBytes(n)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export function b64e(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64d(str) {
  if (typeof str !== 'string') throw new CryptoError('Повреждённые данные');
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// Каноничный JSON (ключи по алфавиту) - чтобы подпись не зависела от порядка полей
export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort()
    .filter(k => v[k] !== undefined)
    .map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}

// ---------- мастер-пароль ----------

export async function deriveMasterKey(password, kdf) {
  if (kdf.alg !== 'argon2id') throw new CryptoError('Неизвестный алгоритм ключа');
  // Границы, чтобы подменённые параметры не подвесили устройство
  if (!(kdf.m >= 16384 && kdf.m <= 262144 && kdf.t >= 1 && kdf.t <= 10 && kdf.p >= 1 && kdf.p <= 4)) {
    throw new CryptoError('Недопустимые параметры ключа');
  }
  return globalThis.hashwasm.argon2id({
    password: password.normalize('NFC'),
    salt: b64d(kdf.salt),
    parallelism: kdf.p,
    iterations: kdf.t,
    memorySize: kdf.m,
    hashLength: 32,
    outputType: 'binary',
  });
}

export function newKdf() {
  return { ...KDF_DEFAULT, salt: b64e(randomBytes(16)) };
}

// ---------- симметричное шифрование ----------

async function aesKey(raw) {
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encryptBytes(keyRaw, data, ad) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(ad) }, await aesKey(keyRaw), data);
  return { iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
}

export async function decryptBytes(keyRaw, box, ad) {
  try {
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: b64d(box.iv), additionalData: te.encode(ad) },
      await aesKey(keyRaw), b64d(box.ct));
    return new Uint8Array(pt);
  } catch {
    throw new CryptoError('Не удалось расшифровать');
  }
}

export async function encryptJSON(keyRaw, obj, ad) {
  return encryptBytes(keyRaw, te.encode(JSON.stringify(obj)), ad);
}

export async function decryptJSON(keyRaw, box, ad) {
  return JSON.parse(td.decode(await decryptBytes(keyRaw, box, ad)));
}

// ---------- ключи участника ----------

export async function generateUserKeys() {
  const box = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const sign = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = async (k, f) => b64e(new Uint8Array(await subtle.exportKey(f, k)));
  return {
    boxPk: await raw(box.publicKey, 'raw'),
    boxSk: await raw(box.privateKey, 'pkcs8'),
    signPk: await raw(sign.publicKey, 'raw'),
    signSk: await raw(sign.privateKey, 'pkcs8'),
  };
}

export function importBoxSk(b64) {
  return subtle.importKey('pkcs8', b64d(b64), { name: 'X25519' }, false, ['deriveBits']);
}

export function importSignSk(b64) {
  return subtle.importKey('pkcs8', b64d(b64), { name: 'Ed25519' }, false, ['sign']);
}

// ---------- запечатывание для получателя (X25519 + HKDF + AES-GCM) ----------

const SEAL_INFO = te.encode('keybox/seal/v1');

async function hkdf(ikm, salt, info) {
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, 256));
}

export async function sealTo(recipientPkB64, data, ad) {
  const recipientPk = b64d(recipientPkB64);
  const eph = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pub = await subtle.importKey('raw', recipientPk, { name: 'X25519' }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, eph.privateKey, 256));
  const epk = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const key = await hkdf(shared, concat(epk, recipientPk), SEAL_INFO);
  return { epk: b64e(epk), ...(await encryptBytes(key, data, ad)) };
}

export async function openSealed(boxSkKey, myPkB64, sealed, ad) {
  try {
    const epk = b64d(sealed.epk);
    const pub = await subtle.importKey('raw', epk, { name: 'X25519' }, false, []);
    const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, boxSkKey, 256));
    const key = await hkdf(shared, concat(epk, b64d(myPkB64)), SEAL_INFO);
    return await decryptBytes(key, sealed, ad);
  } catch {
    throw new CryptoError('Не удалось открыть ключ');
  }
}

// ---------- подписи ----------

export async function signObj(signSkKey, obj) {
  return b64e(new Uint8Array(await subtle.sign('Ed25519', signSkKey, te.encode(canonical(obj)))));
}

export async function verifyObj(signPkB64, sig, obj) {
  try {
    const pk = await subtle.importKey('raw', b64d(signPkB64), 'Ed25519', false, ['verify']);
    return await subtle.verify('Ed25519', pk, b64d(sig), te.encode(canonical(obj)));
  } catch {
    return false;
  }
}

// ---------- проверочный код (сверяется голосом или в мессенджере) ----------

export async function fingerprint(...parts) {
  const h = new Uint8Array(await subtle.digest('SHA-256', te.encode(parts.join('|'))));
  const groups = [];
  for (let i = 0; i < 5; i++) {
    const n = ((h[i * 3] << 16) | (h[i * 3 + 1] << 8) | h[i * 3 + 2]) % 10000;
    groups.push(String(n).padStart(4, '0'));
  }
  return groups.join(' ');
}

export async function sha256b64(text) {
  return b64e(new Uint8Array(await subtle.digest('SHA-256', te.encode(text))));
}

// Браузер поддерживает всё, что нужно?
export async function checkSupport() {
  try {
    await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    return !!globalThis.hashwasm;
  } catch {
    return false;
  }
}
