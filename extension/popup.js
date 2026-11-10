// Окно расширения «Ключница»: вход в команду, список записей, автозаполнение.
// Только DOM + textContent; секреты не пишутся в console и не показываются в DOM.
import * as V from './lib/js/vault.js';
import { ApiStorage, CachedStorage, ApiError, NetworkError } from './lib/js/storage.js';
import * as T from './lib/js/tools.js';
import { API_URL, APP_VERSION } from './lib/js/config.js';
import { itemMatches, fillable } from './match.js';
import { fillForm } from './fill.js';

const ext = globalThis.browser || globalThis.chrome;
const app = document.getElementById('app');
const LOCK_CHOICES = [1, 5, 15, 60, 240];
const CLIP_MS = 30000;

// ---------- настройки (localStorage, префикс kb.) ----------
const LS = {
  get(k) { try { const v = localStorage.getItem('kb.' + k); return v == null ? null : JSON.parse(v); } catch { return null; } },
  set(k, v) { try { localStorage.setItem('kb.' + k, JSON.stringify(v)); } catch { /* нет места */ } },
  del(k) { try { localStorage.removeItem('kb.' + k); } catch { /* нет доступа */ } },
  keys() { try { return Object.keys(localStorage).filter(k => k.startsWith('kb.')).map(k => k.slice(3)); } catch { return []; } },
};
const lockMin = () => { const v = Number(LS.get('lockMin')); return LOCK_CHOICES.includes(v) ? v : 15; };

const state = { team: null, storage: null, session: null, tab: null, search: '', pendingUid: null, pending: null };

// ---------- DOM ----------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const show = (...nodes) => app.replaceChildren(...nodes);
const toastEl = h('div', { class: 'toast', role: 'status', 'aria-live': 'polite' });
let toastT;
function toast(msg, kind = '') {
  toastEl.textContent = msg;
  toastEl.className = 'toast show ' + kind;
  clearTimeout(toastT);
  toastT = setTimeout(() => { toastEl.className = 'toast'; }, 3000);
  if (!toastEl.isConnected) document.body.append(toastEl);
}
const errText = e => (e instanceof NetworkError ? 'Нет связи с сервером. Проверьте интернет.' : (e && e.message) || 'Ошибка');
const paint = () => new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)));

function card(title, sub, ...body) {
  return show(h('main', { class: 'auth' },
    h('div', { class: 'brand' }, 'Ключница'),
    h('h1', null, title),
    sub ? h('p', { class: 'muted' }, sub) : null,
    ...body));
}
const spinner = () => h('div', { class: 'spinner', role: 'status', 'aria-label': 'Загрузка' });

// ---------- сессия в ext.storage.session ----------
async function touch() {
  if (!state.session) return;
  try {
    const { unlocked } = await ext.storage.session.get('unlocked');
    if (unlocked) await ext.storage.session.set({ unlocked: { ...unlocked, lastActive: Date.now() } });
    await ext.alarms.clear('kb-lock');
    ext.alarms.create('kb-lock', { delayInMinutes: lockMin() });
  } catch { /* не критично */ }
}
async function saveUnlocked(s) {
  await ext.storage.session.set({ unlocked: { uid: s.me.uid, name: s.me.name, secret: s.me.secret, lastActive: Date.now() } });
  await ext.alarms.clear('kb-lock');
  ext.alarms.create('kb-lock', { delayInMinutes: lockMin() });
}
async function lock() {
  state.session = null; state.pending = null;
  try { await ext.storage.session.remove('unlocked'); await ext.alarms.clear('kb-lock'); } catch { /* ignore */ }
  start();
}

// ---------- буфер обмена ----------
let clipT = null;
async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(String(text || ''));
    toast(what + ' скопирован' + (what.endsWith('а') ? 'а' : '') + '. Буфер очистится через 30 с.', 'ok');
    clearTimeout(clipT);
    clipT = setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); clipT = null; }, CLIP_MS);
  } catch { toast('Не удалось скопировать', 'error'); }
  touch();
}
addEventListener('pagehide', () => { if (clipT) { try { navigator.clipboard.writeText(''); } catch { /* окно закрывается */ } } });

// ---------- ссылка ----------
const codeDigits = c => String(c || '').replace(/\D/g, '');
function parseLink(text) {
  const hash = String(text || '').trim().split('#')[1];
  if (!hash || !/(^|&)t=/.test(hash)) throw new Error('Это не ссылка Ключницы. Скопируйте ссылку целиком, вместе с частью после #.');
  const p = new URLSearchParams(hash);
  const team = { secret: p.get('t'), code: codeDigits(p.get('c')) };
  if (!team.secret) throw new Error('В ссылке нет ключа команды.');
  if (team.code.length !== 20) throw new Error('В ссылке нет кода команды из 20 цифр. Попросите у админа новую ссылку.');
  return { team, uid: V.isUid(p.get('u')) ? p.get('u') : null };
}
function forgetDevice() {
  for (const k of LS.keys()) if (k !== 'lockMin') LS.del(k);
  state.team = null; state.storage = null;
}
function makeStorage(team) {
  const st = new CachedStorage(new ApiStorage(API_URL, team.secret), 'team');
  st.login = (u, k) => st.inner.login(u, k); // ответ входа не кэшируем на диск (офлайн-перебор)
  return st;
}

function screenNoTeam(msg) {
  const input = h('textarea', { rows: 3, 'aria-label': 'Ссылка Ключницы', placeholder: 'https://…/#t=…&c=…', autocomplete: 'off', spellcheck: 'false' });
  const err = h('p', { class: 'error', role: 'alert' }, msg || '');
  card('Подключить команду', 'Вставьте ссылку Ключницы, которую дал админ.',
    h('form', {
      onsubmit: e => {
        e.preventDefault();
        try {
          const { team, uid } = parseLink(input.value);
          input.value = '';
          const cur = LS.get('team');
          if (cur && cur.code !== team.code) forgetDevice();
          LS.set('team', team);
          state.pendingUid = uid;
          start();
        } catch (ex) { err.textContent = ex.message; }
      },
    }, h('label', null, 'Вставьте ссылку Ключницы', input), err,
    h('button', { class: 'btn primary wide', type: 'submit' }, 'Продолжить')));
  input.focus();
}

async function screenEntry() {
  card('Загрузка…', null, spinner());
  let r;
  try { r = await V.readOrg(state.storage); } catch (e) {
    if (e instanceof ApiError && e.status === 403) return screenNoTeam('Эта ссылка команды больше не действует. Попросите у админа новую.');
    if (e instanceof ApiError && e.status === 404) return screenNoTeam('Команда на сервере ещё не создана.');
    return card('Нет связи с сервером', errText(e), h('button', { class: 'btn primary wide', onclick: () => screenEntry() }, 'Повторить'));
  }
  if (!r) return screenNoTeam('Команда на сервере ещё не создана.');
  if (codeDigits(await V.teamCode(r.org)) !== state.team.code) {
    return card('Ссылка не совпадает с командой', 'Код команды на сервере не тот, что в вашей ссылке. Ничего не вводите и сообщите владельцу.',
      h('button', { class: 'btn link', onclick: () => { forgetDevice(); start(); } }, 'Забыть эту ссылку'));
  }
  const org = r.org;
  const key = 'uid.' + org.orgId;
  if (state.pendingUid) { LS.set(key, state.pendingUid); state.pendingUid = null; }
  const uid = LS.get(key);
  return V.isUid(uid) ? screenUnlock(uid, org) : screenWho(org);
}

async function screenWho(org) {
  card('Кто вы?', org.name, spinner());
  let people = [];
  try { people = (await V.listPeople(state.storage)).filter(p => p.role !== 'pending'); } catch (e) { toast(errText(e), 'error'); }
  card('Кто вы?', org.name,
    people.length ? h('ul', { class: 'people' }, people.map(p => h('li', null,
      h('button', { class: 'row-btn', onclick: () => { LS.set('uid.' + org.orgId, p.uid); screenUnlock(p.uid, org); } }, p.name))))
      : h('p', { class: 'muted' }, 'Участников нет. Вступите в команду в веб-версии Ключницы.'),
    h('button', { class: 'btn link', onclick: () => { forgetDevice(); start(); } }, 'Другая ссылка'));
}

function screenUnlock(uid, org) {
  const input = h('input', { type: 'password', required: true, autocomplete: 'current-password', 'aria-label': 'Мастер-пароль', id: 'pw' });
  const caps = h('p', { class: 'warn', hidden: true }, 'Включён Caps Lock');
  const capsCheck = e => { caps.hidden = !(e.getModifierState && e.getModifierState('CapsLock')); };
  input.addEventListener('keydown', capsCheck); input.addEventListener('keyup', capsCheck);
  const status = h('p', { class: 'muted small', role: 'status', 'aria-live': 'polite' });
  const err = h('p', { class: 'error', role: 'alert' });
  const who = h('p', { class: 'muted small' });
  const btn = h('button', { class: 'btn primary wide', type: 'submit' }, 'Открыть');
  card('Разблокировать', org.name, who,
    h('form', {
      onsubmit: async e => {
        e.preventDefault();
        err.textContent = '';
        btn.disabled = true; input.readOnly = true;
        btn.textContent = 'Проверяю пароль…';
        status.textContent = 'Проверяю пароль… обычно пара секунд.';
        await paint();
        try {
          const s = await V.unlock(state.storage, uid, input.value, V.localSeen);
          input.value = '';
          status.textContent = 'Загружаю записи…';
          await saveUnlocked(s);
          await enter(s);
        } catch (ex) {
          err.textContent = errText(ex); // в тексте VaultError уже есть число оставшихся попыток
          status.textContent = '';
          btn.disabled = false; input.readOnly = false; btn.textContent = 'Открыть';
          input.select();
        }
      },
    }, h('label', { for: 'pw' }, 'Мастер-пароль'), input, caps, btn, status, err),
    h('button', { class: 'btn link', onclick: () => { LS.del('uid.' + org.orgId); screenWho(org); } }, 'Войти другим участником'));
  input.focus();
  V.listPeople(state.storage).then(ps => { const p = ps.find(x => x.uid === uid); if (p) who.textContent = 'Вы входите как ' + p.name; }).catch(() => {});
}

// ---------- главный экран ----------
async function currentTab() {
  try { const [t] = await ext.tabs.query({ active: true, currentWindow: true }); return t || null; } catch { return null; }
}
async function enter(s) {
  state.session = s;
  await s.loadAll();
  state.tab = await currentTab();
  touch();
  if (await quickFill()) return;
  state.pending = await loadPending(s);
  screenMain();
}

// ---------- хранилище фона (pending / autofill) ----------
async function takeSession(key) {
  try { const r = await ext.storage.session.get(key); return r && r[key] || null; } catch { return null; }
}
async function clearPending() {
  state.pending = null;
  try { await ext.storage.session.remove('pending'); } catch { /* ignore */ }
  try { await ext.action.setBadgeText({ text: '' }); } catch { /* ignore */ }
}

// Горячая клавиша: ровно одна подходящая запись → заполнить и закрыть окно
async function quickFill() {
  const af = await takeSession('autofill');
  if (!af) return false;
  try { await ext.storage.session.remove('autofill'); } catch { /* ignore */ }
  const tab = state.tab;
  if (Date.now() - (af.at || 0) > 10000 || !tab || af.tabId !== tab.id || !fillable(tab.url)) return false;
  const m = state.session.allItems().filter(i => i.type === 'login' && itemMatches(i, tab.url));
  if (m.length !== 1) return false;
  const ok = await doFill(m[0]);
  if (ok) { window.close(); return true; }
  return false;
}

// Пойманный на сайте пароль: решить, что предложить
async function loadPending(s) {
  const p = await takeSession('pending');
  if (!p) return null;
  if (Date.now() - (p.at || 0) > 120000 || !p.origin || !p.password) { await clearPending(); return null; }
  const url = p.origin + '/';
  const same = s.allItems().filter(i => i.type === 'login' && itemMatches(i, url) && (i.username || '') === (p.username || ''));
  if (same.some(i => i.password === p.password)) { await clearPending(); return null; }
  return { ...p, target: same[0] || null };
}

function pendingBanner() {
  const p = state.pending;
  if (!p) return null;
  const s = state.session;
  const host = p.host || T.hostOf(p.origin) || p.origin;
  const err = h('p', { class: 'error', role: 'alert' });
  const later = h('button', { class: 'btn sm', type: 'button', onclick: async () => { await clearPending(); screenMain(); } }, 'Не сейчас');
  const box = h('section', { class: 'save-banner', 'aria-label': 'Сохранение пароля' });
  const run = async (btn, fn) => {
    btn.disabled = true; err.textContent = '';
    try { await fn(); await clearPending(); toast('Сохранено', 'ok'); screenMain(); }
    catch (e) { err.textContent = errText(e); btn.disabled = false; }
    touch();
  };
  if (p.target) {
    const it = p.target;
    const btn = h('button', { class: 'btn primary sm', type: 'button',
      onclick: () => run(btn, () => s.saveItem(it.cid, { ...it, password: p.password })) }, 'Обновить');
    box.append(h('strong', null, 'Обновить пароль для ' + host + '?'),
      h('span', { class: 'muted small' }, [it.name, it.username].filter(Boolean).join(' · ')),
      p.isNew ? h('p', { class: 'muted small' }, 'Это похоже на новый пароль.') : null,
      h('div', { class: 'actions' }, btn, later), err);
    return box;
  }
  const name = h('input', { type: 'text', 'aria-label': 'Название', value: host.replace(/^www\./, '') });
  const user = h('input', { type: 'text', 'aria-label': 'Логин', autocomplete: 'off', value: p.username || '' });
  const cols = s.collections();
  const sel = h('select', { 'aria-label': 'Коллекция' }, cols.map(c => h('option', { value: c.cid }, c.name || 'Без названия')));
  sel.value = s.personalCid;
  const btn = h('button', { class: 'btn primary sm', type: 'submit' }, 'Сохранить');
  box.append(h('strong', null, 'Сохранить пароль для ' + host + '?'),
    p.isNew ? h('p', { class: 'muted small' }, 'Это похоже на новый пароль.') : null,
    h('form', { onsubmit: e => {
      e.preventDefault();
      const item = { id: randomId(), type: 'login', name: name.value.trim() || host, username: user.value.trim(), password: p.password,
        uris: [p.origin], totp: '', notes: '', favorite: false };
      run(btn, () => s.saveItem(sel.value, item));
    } },
    h('label', null, 'Название', name), h('label', null, 'Логин', user), h('label', null, 'Коллекция', sel),
    h('div', { class: 'actions' }, btn, later)), err);
  return box;
}
function randomId() {
  const b = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}

// ---------- генератор ----------
function screenGenerator() {
  touch();
  const opts = { length: 20, lower: true, upper: true, digits: true, symbols: true, ...(LS.get('gen') || {}) };
  const out = h('div', { class: 'gen-out mono', 'aria-live': 'polite' });
  const meter = h('div', { class: 'muted small' });
  const bar = h('div', { class: 'meter' }, h('span'));
  const len = h('input', { type: 'range', min: 8, max: 64, value: String(opts.length), 'aria-label': 'Длина' });
  const lenLabel = h('span', { class: 'mono' });
  const make = () => {
    opts.length = Number(len.value);
    lenLabel.textContent = opts.length;
    LS.set('gen', { length: opts.length, lower: opts.lower, upper: opts.upper, digits: opts.digits, symbols: opts.symbols });
    let pw = '';
    try { pw = T.generatePassword(opts); } catch { pw = ''; }
    out.textContent = pw || 'Выберите хотя бы один набор символов';
    const st = T.strength(pw);
    meter.textContent = pw ? st.label + ' · ~' + st.bits + ' бит' : '';
    bar.dataset.level = String(st.level);
    touch();
  };
  len.addEventListener('input', make);
  const toggle = (key, label) => h('label', { class: 'check' },
    h('input', { type: 'checkbox', checked: opts[key], onchange: e => { opts[key] = e.target.checked; make(); } }), label);
  show(h('header', { class: 'top' },
    h('button', { class: 'icon', 'aria-label': 'Назад', onclick: () => screenMain() }, '←'),
    h('span', { class: 'team' }, 'Генератор паролей')),
  h('main', { class: 'settings' },
    out, bar, meter,
    h('div', { class: 'actions' },
      h('button', { class: 'btn', onclick: make }, 'Ещё раз'),
      h('button', { class: 'btn primary', onclick: () => { const v = out.textContent; if (T.strength(v).level && !/^Выберите/.test(v)) copy(v, 'Пароль'); } }, 'Копировать')),
    h('div', { class: 'range' }, h('span', null, 'Длина'), len, lenLabel),
    toggle('lower', 'Строчные a-z'), toggle('upper', 'Заглавные A-Z'), toggle('digits', 'Цифры 0-9'), toggle('symbols', 'Символы !@#…')));
  make();
}

function originOf(url) { try { return new URL(url).origin; } catch { return null; } }

async function doFill(item, { totp } = {}) {
  touch();
  const tab = await currentTab();
  const url = tab && tab.url;
  if (!url || !fillable(url) || !itemMatches(item, url) || !state.tab || originOf(url) !== originOf(state.tab.url)) {
    toast('Вкладка сменилась или не подходит к записи — заполнение отменено.', 'error');
    return false;
  }
  const args = { origin: originOf(url), username: totp ? '' : item.username || '', password: totp ? '' : item.password || '', totp: totp || '' };
  try {
    const [res] = await ext.scripting.executeScript({ target: { tabId: tab.id }, func: fillForm, args: [args] });
    const r = res && res.result;
    if (r && r.ok) { toast('Заполнено', 'ok'); if (!totp) setTimeout(() => window.close(), 400); return true; }
    toast('Не нашёл поля для заполнения' + (r && r.reason ? ': ' + r.reason : ''), 'error');
  } catch { toast('Нет доступа к этой странице', 'error'); }
  return false;
}

async function copyTotp(item, matched) {
  try {
    const code = await T.totpCode(item.totp, state.storage.now ? state.storage.now() : Date.now());
    await copy(code, 'Код');
    if (matched && fillable(state.tab && state.tab.url)) doFill(item, { totp: code });
  } catch { toast('Не удалось получить код 2FA', 'error'); }
}

function itemRow(item, matched) {
  const host = (item.uris || []).map(T.hostOf).find(Boolean) || '';
  const canFill = matched && fillable(state.tab && state.tab.url);
  const first = (item.uris || []).map(T.safeUrl).find(Boolean);
  return h('li', { class: 'item' + (matched ? ' match' : '') },
    h('div', { class: 'item-head' },
      h('div', { class: 'item-title' },
        h('strong', null, item.name || host || 'Без названия'),
        h('span', { class: 'muted small' }, [item.username, host].filter(Boolean).join(' · ')),
        matched ? h('span', { class: 'badge' }, 'подходит к сайту') : null),
      first && !matched ? h('button', { class: 'icon', 'aria-label': 'Открыть сайт ' + host, title: 'Открыть сайт',
        onclick: () => { ext.tabs.create({ url: first }); window.close(); } }, '↗') : null),
    h('div', { class: 'actions' },
      canFill ? h('button', { class: 'btn primary sm', onclick: () => doFill(item) }, 'Заполнить') : null,
      item.username ? h('button', { class: 'btn sm', onclick: () => copy(item.username, 'Логин') }, 'Логин') : null,
      item.password ? h('button', { class: 'btn sm', onclick: () => copy(item.password, 'Пароль') }, 'Пароль') : null,
      item.totp ? h('button', { class: 'btn sm', onclick: () => copyTotp(item, matched) }, 'Код 2FA') : null));
}

function screenMain() {
  const s = state.session;
  const list = h('ul', { class: 'items', 'aria-label': 'Записи' });
  const tabUrl = state.tab && state.tab.url;
  const all = s.allItems().filter(i => i.type === 'login');
  let matchedNow = [];
  const render = () => {
    const q = state.search.trim().toLowerCase();
    const hit = i => !q || [i.name, i.username, ...(i.uris || [])].some(v => String(v || '').toLowerCase().includes(q));
    const items = all.filter(hit);
    const m = tabUrl ? items.filter(i => itemMatches(i, tabUrl)) : [];
    const rest = items.filter(i => !m.includes(i)).sort((a, b) => String(a.name).localeCompare(String(b.name), 'ru'));
    matchedNow = m;
    list.replaceChildren(...m.map(i => itemRow(i, true)), ...rest.map(i => itemRow(i, false)));
    if (!items.length) list.append(h('li', { class: 'empty muted' }, q ? 'Ничего не найдено' : 'Записей пока нет'));
  };
  const search = h('input', { type: 'search', placeholder: 'Поиск', 'aria-label': 'Поиск записей', value: state.search,
    oninput: e => { state.search = e.target.value; render(); touch(); },
    onkeydown: e => { if (e.key === 'Enter' && matchedNow.length === 1 && fillable(tabUrl)) { e.preventDefault(); doFill(matchedNow[0]); } } });
  show(h('header', { class: 'top' },
    h('span', { class: 'team' }, s.org && s.org.name || 'Ключница'),
    h('button', { class: 'icon', 'aria-label': 'Генератор паролей', title: 'Генератор паролей', onclick: screenGenerator }, '🎲'),
    h('button', { class: 'btn sm', onclick: lock }, 'Заблокировать'),
    h('button', { class: 'icon', 'aria-label': 'Настройки', title: 'Настройки', onclick: screenSettings }, '⚙')),
  pendingBanner(), h('div', { class: 'search' }, search), list);
  render();
  if (!state.pending) search.focus();
}

function screenSettings() {
  touch();
  const sel = h('select', { id: 'lock', onchange: e => { LS.set('lockMin', Number(e.target.value)); touch(); toast('Сохранено', 'ok'); } },
    LOCK_CHOICES.map(m => { const o = h('option', { value: String(m) }, m < 60 ? m + ' мин' : m / 60 + ' ч'); if (m === lockMin()) o.selected = true; return o; }));
  show(h('header', { class: 'top' },
    h('button', { class: 'icon', 'aria-label': 'Назад', onclick: () => (state.session ? screenMain() : start()) }, '←'),
    h('span', { class: 'team' }, 'Настройки')),
  h('main', { class: 'settings' },
    h('label', { for: 'lock' }, 'Автоблокировка через'), sel,
    h('button', { class: 'btn danger wide', onclick: async () => {
      if (!confirm('Забыть это устройство? Понадобится снова вставить ссылку команды.')) return;
      forgetDevice();
      await lock();
    } }, 'Забыть это устройство'),
    h('p', { class: 'muted small' }, 'Ключница ' + APP_VERSION)));
}

// ---------- запуск ----------
async function start() {
  state.team = LS.get('team');
  if (!state.team || !state.team.secret || codeDigits(state.team.code).length !== 20) return screenNoTeam();
  state.storage = makeStorage(state.team);
  try {
    const { unlocked } = await ext.storage.session.get('unlocked');
    if (unlocked) {
      if (Date.now() - (unlocked.lastActive || 0) < lockMin() * 60000) {
        card('Загрузка…', null, spinner());
        try {
          const s = await V.resume(state.storage, unlocked.uid, unlocked.name, unlocked.secret, V.localSeen);
          return await enter(s);
        } catch (e) { toast(errText(e), 'error'); }
      }
      await ext.storage.session.remove('unlocked');
    }
  } catch { /* storage.session недоступен */ }
  return screenEntry();
}

start();
