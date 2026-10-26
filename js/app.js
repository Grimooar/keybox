// Ключница - интерфейс приложения

import { API_URL, APP_VERSION } from './config.js';
import * as C from './crypto.js';
import { ApiStorage, ApiError, CachedStorage, MemoryStorage, NetworkError } from './storage.js';
import * as V from './vault.js';
import * as T from './tools.js';
import { h, icon, iconBtn, clear, toast, modal, confirmDialog, field, formatDate, avatar } from './ui.js';

const $app = document.getElementById('app');

const LS = {
  get(k, d = null) { try { const v = localStorage.getItem('kb.' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('kb.' + k, JSON.stringify(v)); } catch { /* приватный режим */ } },
  del(k) { try { localStorage.removeItem('kb.' + k); } catch { /* нет доступа */ } },
};

const state = {
  storage: null,
  team: null,           // { secret, code } из ссылки команды
  demo: false,
  session: null,
  orgName: '',
  view: 'all',          // all | fav | <cid> | team | settings | generator
  search: '',
  sel: null,            // { cid, id }
  editing: null,        // { draft, cid, fromCid, isNew }
  reveal: false,
  navOpen: false,
  syncedAt: 0,
  syncing: false,
};

let timers = [];
const clearTimers = () => { timers.forEach(clearInterval); timers = []; };

// ---------- общее ----------

async function run(fn, btn) {
  if (btn) btn.disabled = true;
  try {
    return await fn();
  } catch (e) {
    console.error(e);
    toast(e.message || String(e), 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

let clipTimer = null;
// secret = false - для ссылок и адресов: их не стираем из буфера
async function copy(text, what = 'Скопировано', secret = true) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast('Не удалось скопировать', 'error');
    return;
  }
  if (!secret) return toast(what);
  toast(what + '. Буфер очистится через 30 с');
  clearTimeout(clipTimer);
  clipTimer = setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText('');
    } catch {
      // Нет доступа на чтение - очищаем без проверки, если вкладка активна
      if (document.hasFocus()) navigator.clipboard.writeText('').catch(() => {});
    }
  }, 30000);
}

function authCard(title, subtitle, ...body) {
  clearTimers();
  clear($app).append(h('main', { class: 'auth' },
    h('div', { class: 'auth-card' },
      h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, icon('key')), h('span', null, 'Ключница')),
      h('h1', null, title),
      subtitle ? h('p', { class: 'muted' }, subtitle) : null,
      ...body)));
  $app.querySelector('input')?.focus();
}

function passwordInput(attrs = {}) {
  const input = h('input', { type: 'password', autocomplete: 'current-password', spellcheck: 'false', ...attrs });
  const btn = iconBtn('eye', 'Показать пароль', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    clear(btn).append(icon(show ? 'eyeOff' : 'eye'));
  });
  return { input, el: h('div', { class: 'input-group' }, input, btn) };
}

function strengthMeter(input) {
  const bar = h('span', { class: 'meter-bar' });
  const label = h('span', { class: 'meter-label' });
  const el = h('div', { class: 'meter' }, h('span', { class: 'meter-track' }, bar), label);
  const update = () => {
    const s = T.strength(input.value);
    bar.style.width = (s.level * 25) + '%';
    bar.dataset.level = s.level;
    label.textContent = s.label;
  };
  input.addEventListener('input', update);
  update();
  return el;
}

function masterPasswordFields() {
  const p1 = passwordInput({ autocomplete: 'new-password', required: true, minlength: 12 });
  const p2 = passwordInput({ autocomplete: 'new-password', required: true });
  return {
    els: [
      field('Мастер-пароль', [p1.el, strengthMeter(p1.input)], 'Не меньше 12 символов. Лучше всего фраза из 4-5 случайных слов.'),
      field('Повторите мастер-пароль', p2.el),
      h('p', { class: 'warn' }, icon('shield'), 'Мастер-пароль нигде не хранится и не восстанавливается. Если забудете, доступ к данным пропадёт. Запишите его и уберите в надёжное место.'),
    ],
    value() {
      const a = p1.input.value;
      // Файлы участников видит вся команда, поэтому пароль должен выдерживать перебор
      if (a.length < 12) throw new Error('Мастер-пароль слишком короткий, нужно хотя бы 12 символов');
      if (T.strength(a).level < 3) throw new Error('Мастер-пароль слишком простой: добавьте слов или разных символов');
      if (a !== p2.input.value) throw new Error('Пароли не совпадают');
      return a;
    },
  };
}

// ---------- запуск ----------

async function start() {
  // Защита от встраивания в чужой сайт (кликджекинг): GitHub Pages не даёт поставить заголовок
  if (window.top !== window.self) {
    clear($app).append(h('main', { class: 'auth' }, h('p', null, 'Ключница не работает внутри чужих страниц. Откройте её напрямую.')));
    return;
  }
  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
  if (!await C.checkSupport()) return screenUnsupported();
  // Тестовый режим для разработки: только localhost, данные в памяти вкладки
  if (location.hash === '#demo' && ['localhost', '127.0.0.1'].includes(location.hostname)) {
    state.demo = true;
    state.storage ||= new MemoryStorage();
    return screenEntry();
  }
  readLink();
  state.team = LS.get('team');
  const setupCode = sessionGet('setup');
  if (setupCode && !state.team) return screenCreateTeam(setupCode);
  if (!state.team) return screenNoTeam();
  state.storage = new CachedStorage(new ApiStorage(API_URL, state.team.secret), 'team');
  state.storage.invite = sessionGet('invite');
  return screenEntry();
}

function sessionGet(k) { try { return sessionStorage.getItem('kb.' + k); } catch { return null; } }
function sessionSet(k, v) { try { v == null ? sessionStorage.removeItem('kb.' + k) : sessionStorage.setItem('kb.' + k, v); } catch { /* нет доступа */ } }

const codeDigits = code => String(code || '').replace(/\D/g, '');

// Ссылки (всё после #, на сервер GitHub это не уходит):
//   #setup=<код>                        - создать команду (один раз, ссылку даёт установщик)
//   #t=<секрет команды>&c=<код команды> - вход в команду с нового устройства
//   ...&i=<приглашение>                 - то же + заявка на вступление
function readLink() {
  const p = new URLSearchParams(location.hash.slice(1));
  if (!p.has('setup') && !p.has('t')) return;
  history.replaceState(null, '', location.pathname); // секреты не остаются в адресной строке
  if (p.has('setup')) sessionSet('setup', p.get('setup'));
  if (p.has('t')) {
    const team = { secret: p.get('t'), code: codeDigits(p.get('c')) };
    const cur = LS.get('team');
    if (cur && cur.secret !== team.secret) forgetDevice();
    LS.set('team', team);
  }
  if (p.has('i')) sessionSet('invite', p.get('i'));
}

function teamLink(invite) {
  const p = new URLSearchParams({ t: state.team.secret, c: state.team.code });
  if (invite) p.set('i', invite);
  return location.origin + location.pathname + '#' + p;
}

function forgetDevice() {
  try {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k?.startsWith('kb.') && !k.startsWith('kb.gen') && !k.startsWith('kb.lockMin')) localStorage.removeItem(k);
    }
  } catch { /* нет доступа */ }
  sessionSet('invite', null);
}

function screenUnsupported() {
  authCard('Браузер устарел', 'Нужен свежий Chrome, Edge, Safari 17+ или Firefox 130+: в старых нет нужного шифрования.');
}

function screenNoTeam(message) {
  authCard('Нужна ссылка команды', message || 'Ключница открывается по ссылке от владельца или админа команды. Попросите её: раздел «Команда» → «Пригласить».',
    h('p', { class: 'muted small' }, 'Если вы уже в команде и открыли Ключницу на новом устройстве, возьмите ссылку на старом: «Настройки» → «Вход с другого устройства».'));
}

async function screenEntry() {
  authCard('Загрузка…', null, h('div', { class: 'spinner' }));
  let r;
  try {
    r = await V.readOrg(state.storage);
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) {
      return screenNoTeam('Эта ссылка команды больше не действует. Попросите у админа новую.');
    }
    if (e instanceof ApiError && e.status === 404 && !state.demo) return screenNoTeam('Команда на сервере ещё не создана.');
    return authCard('Нет связи с сервером', e instanceof NetworkError ? 'Проверьте интернет и попробуйте ещё раз.' : e.message,
      h('button', { class: 'btn primary wide', onclick: () => screenEntry() }, 'Повторить'));
  }
  if (!r) return state.demo ? screenCreateTeam(null) : screenNoTeam();
  // Код команды из ссылки - защита от подмены: сервер не может выдать чужую «команду»
  const code = await V.teamCode(r.org);
  if (!state.demo && state.team.code && codeDigits(code) !== state.team.code) {
    return authCard('Ссылка не совпадает с командой', 'Код команды на сервере не тот, что в вашей ссылке. Ничего не вводите и сообщите владельцу.',
      h('button', { class: 'btn link', onclick: () => { forgetDevice(); start(); } }, 'Забыть эту ссылку'));
  }
  state.orgName = r.org.name;
  if (state.storage.invite) return screenJoinForm(r.org);
  const uid = LS.get('uid.' + r.org.orgId);
  if (uid) return screenUnlock(uid, r.org);
  return screenWho(r.org);
}

function screenCreateTeam(setupCode) {
  const team = h('input', { required: true, placeholder: 'например, GearPoint', maxlength: 60 });
  const name = h('input', { required: true, placeholder: 'как вас будут видеть коллеги', maxlength: 60, autocomplete: 'name' });
  const mp = masterPasswordFields();
  authCard('Новая команда', 'Создайте команду, вы будете её владельцем. Потом пригласите коллег ссылкой.',
    h('form', {
      onsubmit: e => {
        e.preventDefault();
        const btn = e.currentTarget.querySelector('button[type=submit]');
        run(async () => {
          const password = mp.value();
          btn.textContent = 'Создаю ключи…';
          let setup = null;
          if (!state.demo) {
            const secret = C.b64e(C.randomBytes(24));
            state.storage = new CachedStorage(new ApiStorage(API_URL, secret), 'team');
            setup = { setupCode, teamHash: await C.sha256b64(secret) };
            state.team = { secret };
          }
          const s = await V.createTeam(state.storage, { teamName: team.value.trim(), userName: name.value.trim(), password, seen: V.localSeen, setup });
          if (!state.demo) {
            state.team.code = codeDigits(await V.teamCode(s.org));
            LS.set('team', state.team);
            sessionSet('setup', null);
          }
          LS.set('uid.' + s.orgId, s.me.uid);
          await enter(s);
          toast('Команда создана');
        }, btn).finally(() => { btn.textContent = 'Создать команду'; });
      },
    },
    field('Название команды', team),
    field('Ваше имя', name),
    ...mp.els,
    h('button', { class: 'btn primary wide', type: 'submit' }, 'Создать команду')));
}

async function screenWho(org) {
  let people = [];
  try { people = await V.listPeople(state.storage); } catch (e) { toast(e.message, 'error'); }
  const roles = { owner: 'владелец', admin: 'админ', member: '', pending: 'ждёт одобрения' };
  authCard(org.name, 'Кто вы?',
    h('div', { class: 'people' }, people.map(p =>
      h('button', { class: 'person', onclick: () => screenUnlock(p.uid, org) },
        avatar(p.name), h('span', { class: 'person-name' }, p.name), roles[p.role] ? h('span', { class: 'tag' }, roles[p.role]) : null))),
    state.demo
      ? h('button', { class: 'btn primary wide', onclick: () => screenJoinForm(org) }, icon('plus'), 'Я новый участник')
      : h('p', { class: 'muted small center' }, 'Новенький? Попросите у админа ссылку-приглашение.'));
}

function screenJoinForm(org) {
  const name = h('input', { required: true, maxlength: 60, autocomplete: 'name' });
  const mp = masterPasswordFields();
  authCard('Вступить в «' + org.name + '»', 'Придумайте мастер-пароль. Владелец или админ подтвердит заявку, а пока можно пользоваться личным сейфом.',
    h('form', {
      onsubmit: e => {
        e.preventDefault();
        const btn = e.currentTarget.querySelector('button[type=submit]');
        run(async () => {
          const password = mp.value();
          const s = await V.joinTeam(state.storage, { userName: name.value.trim(), password, seen: V.localSeen, expectedTeamCode: await V.teamCode(org) });
          state.storage.invite = null;
          sessionSet('invite', null);
          LS.set('uid.' + s.orgId, s.me.uid);
          await screenJoined(s);
        }, btn);
      },
    },
    field('Ваше имя', name),
    ...mp.els,
    h('button', { class: 'btn primary wide', type: 'submit' }, 'Отправить заявку')),
    h('button', { class: 'btn link', onclick: () => { state.storage.invite = null; sessionSet('invite', null); screenWho(org); } }, 'У меня уже есть аккаунт'));
}

async function screenJoined(s) {
  const mine = await s.myCode();
  authCard('Заявка отправлена', 'Назовите этот код админу голосом или в мессенджере. Он примет заявку, только если коды совпадут.',
    h('div', { class: 'codes' },
      h('div', null, h('span', { class: 'muted' }, 'Ваш код'), h('strong', { class: 'code' }, mine))),
    h('button', { class: 'btn primary wide', onclick: () => run(() => enter(s)) }, 'Продолжить'));
}

function screenUnlock(uid, org) {
  const pw = passwordInput({ required: true, autocomplete: 'current-password' });
  pw.input.setAttribute('autocomplete', 'current-password');
  authCard('Разблокировать', org.name,
    h('form', {
      onsubmit: e => {
        e.preventDefault();
        const btn = e.currentTarget.querySelector('button[type=submit]');
        btn.textContent = 'Открываю…';
        run(async () => {
          const s = await V.unlock(state.storage, uid, pw.input.value, V.localSeen);
          pw.input.value = '';
          LS.set('uid.' + s.orgId, uid);
          await enter(s);
        }, btn).finally(() => { btn.textContent = 'Открыть'; pw.input.select(); });
      },
    },
    field('Мастер-пароль', pw.el),
    h('button', { class: 'btn primary wide', type: 'submit' }, 'Открыть')),
    h('button', { class: 'btn link', onclick: () => { LS.del('uid.' + org.orgId); screenWho(org); } }, 'Войти другим участником'));
}

async function enter(s) {
  state.session = s;
  state.orgName = s.org.name;
  state.view = 'all';
  state.sel = null;
  state.editing = null;
  state.search = '';
  await s.loadAll();
  state.syncedAt = Date.now();
  renderMain();
  if (s.isAdmin) refreshPendingCount();
}

function lock() {
  state.session = null;
  state.editing = null;
  state.sel = null;
  clearTimers();
  document.querySelectorAll('.modal-wrap').forEach(m => m.remove());
  if (clipTimer) {
    clearTimeout(clipTimer);
    clipTimer = null;
    navigator.clipboard.writeText('').catch(() => {});
  }
  start();
}

// ---------- синхронизация ----------

async function sync(manual = false) {
  const s = state.session;
  if (!s || state.syncing) return;
  state.syncing = true;
  renderSyncStatus();
  try {
    await s.refresh();
    await s.loadAll();
    state.syncedAt = Date.now();
    if (state.session !== s) return;
    renderNav();
    if (!state.editing) renderContent();
    if (s.isAdmin) refreshPendingCount();
    if (manual) toast(state.storage.offline ? 'Нет сети, показаны сохранённые данные' : 'Обновлено');
  } catch (e) {
    if (e instanceof V.RemovedError || (e instanceof ApiError && e.status === 401 && /удал/i.test(e.message))) {
      // Нас удалили: стираем сохранённые на устройстве данные команды и выходим
      state.storage.clear?.();
      LS.del('uid.' + s.orgId);
      state.syncing = false;
      lock();
      toast(e instanceof V.RemovedError ? e.message : 'Вас удалили из команды. Данные команды больше недоступны.', 'error');
      return;
    }
    if (manual) toast(e.message, 'error');
    else console.warn(e);
  } finally {
    state.syncing = false;
    renderSyncStatus();
  }
}

let pendingCount = 0;
async function refreshPendingCount() {
  try {
    pendingCount = (await state.session.pendingUsers()).length;
    renderNav();
  } catch { /* не критично */ }
}

// ---------- главный экран ----------

let $nav, $content, $main, $sync;

function renderMain() {
  clearTimers();
  $nav = h('nav', { class: 'sidebar', 'aria-label': 'Разделы' });
  $content = h('div', { class: 'content' });
  $main = h('div', { class: 'main' }, $nav, h('div', { class: 'scrim', onclick: () => setNav(false) }), $content);
  clear($app).append($main);
  renderNav();
  renderContent();
}

function setNav(open) {
  state.navOpen = open;
  $main.classList.toggle('nav-open', open);
}

function go(view) {
  state.view = view;
  state.sel = null;
  state.editing = null;
  setNav(false);
  renderNav();
  renderContent();
}

function renderNav() {
  const s = state.session;
  if (!s || !$nav) return;
  const items = s.allItems();
  const count = f => items.filter(f).length;
  const link = (view, ic, label, n, extra) => h('button', {
    class: 'nav-link' + (state.view === view ? ' active' : ''),
    onclick: () => go(view),
    'aria-current': state.view === view ? 'page' : null,
  }, icon(ic), h('span', { class: 'nav-label' }, label), extra, n != null ? h('span', { class: 'count' }, n) : null);

  $sync = h('div', { class: 'sync' });
  clear($nav).append(...[
    h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, icon('key')), h('span', null, 'Ключница')),
    h('div', { class: 'team-name' }, s.org.name),
    link('all', 'grid', 'Все записи', items.length),
    link('fav', 'star', 'Избранное', count(i => i.favorite)),
    h('div', { class: 'nav-title' }, 'Коллекции'),
    s.collections().map(c => link(c.cid, c.personal ? 'user' : c.all ? 'users' : 'folder', c.name, count(i => i.cid === c.cid),
      s.vaults.get(c.cid)?.error ? h('span', { class: 'dot error', title: s.vaults.get(c.cid).error }) : null)),
    h('div', { class: 'nav-title' }, 'Инструменты'),
    link('generator', 'dice', 'Генератор'),
    link('team', 'shield', 'Команда', null, pendingCount && s.isAdmin ? h('span', { class: 'badge' }, pendingCount) : null),
    link('settings', 'sliders', 'Настройки'),
    h('div', { class: 'nav-foot' },
      $sync,
      h('div', { class: 'nav-actions' },
        iconBtn('refresh', 'Обновить', () => sync(true)),
        iconBtn('lock', 'Заблокировать', lock))),
  ].flat());
  renderSyncStatus();
}

function renderSyncStatus() {
  if (!$sync) return;
  const txt = state.syncing ? 'Синхронизация…'
    : state.storage?.offline ? 'Нет сети, данные из кэша'
      : state.syncedAt ? 'Обновлено в ' + new Date(state.syncedAt).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }) : '';
  $sync.textContent = txt;
  $sync.classList.toggle('offline', !!state.storage?.offline);
}

function renderContent() {
  clearTimers();
  if (!$content) return;
  clear($content);
  $main.classList.toggle('show-detail', !!(state.sel || state.editing));
  if (state.view === 'team') return renderTeam();
  if (state.view === 'settings') return renderSettings();
  if (state.view === 'generator') return renderGenerator();
  renderVault();
}

function topBar(title, ...right) {
  return h('header', { class: 'topbar' },
    iconBtn('menu', 'Меню', () => setNav(true), 'mobile-only'),
    h('h1', null, title), h('div', { class: 'spacer' }), ...right);
}

// ---------- записи ----------

function viewTitle() {
  if (state.view === 'all') return 'Все записи';
  if (state.view === 'fav') return 'Избранное';
  return state.session.collectionName(state.view);
}

function filteredItems() {
  const q = state.search.trim().toLowerCase();
  return state.session.allItems()
    .filter(i => state.view === 'all' || (state.view === 'fav' ? i.favorite : i.cid === state.view))
    .filter(i => !q || [i.name, i.username, ...(i.uris || [])].some(v => (v || '').toLowerCase().includes(q)))
    .sort((a, b) => (b.favorite - a.favorite) || a.name.localeCompare(b.name, 'ru'));
}

function renderVault() {
  const s = state.session;
  const search = h('input', {
    type: 'search', placeholder: 'Поиск', value: state.search, 'aria-label': 'Поиск',
    oninput: e => { state.search = e.target.value; renderList(); },
  });
  const $list = h('div', { class: 'items', role: 'list' });
  const $detail = h('section', { class: 'detail' });

  $content.append(
    h('section', { class: 'list-pane' },
      topBar(viewTitle(), iconBtn('plus', 'Новая запись', () => newItem(), 'primary')),
      s.pending ? h('div', { class: 'banner' }, icon('clock'), h('span', null, 'Заявка ждёт одобрения админа. Пока доступен только личный сейф.')) : null,
      h('div', { class: 'search' }, icon('search'), search),
      $list),
    $detail);

  function renderList() {
    const items = filteredItems();
    clear($list);
    if (!items.length) {
      $list.append(h('div', { class: 'empty' },
        state.search ? 'Ничего не найдено' : 'Здесь пока пусто',
        state.search ? null : h('button', { class: 'btn primary', onclick: () => newItem() }, icon('plus'), 'Добавить запись')));
      return;
    }
    for (const it of items) {
      const active = state.sel?.id === it.id && state.sel?.cid === it.cid;
      $list.append(h('button', {
        class: 'item' + (active ? ' active' : ''), role: 'listitem',
        onclick: () => { state.sel = { cid: it.cid, id: it.id }; state.editing = null; state.reveal = false; renderContent(); },
      },
      avatar(it.name),
      h('span', { class: 'item-text' },
        h('span', { class: 'item-name' }, it.name, it.favorite ? icon('star', 'filled small') : null),
        h('span', { class: 'item-sub' }, it.type === 'note' ? 'Заметка' : it.username || T.hostOf(it.uris?.[0] || '') || '—')),
      state.view === 'all' || state.view === 'fav' ? h('span', { class: 'tag' }, s.collectionName(it.cid)) : null));
    }
  }

  renderList();
  if (state.editing) renderEditor($detail);
  else if (state.sel) renderItem($detail);
  else $detail.append(h('div', { class: 'empty big' }, icon('key', 'huge'), 'Выберите запись'));
}

function blankItem() {
  return { id: C.randomHex(8), type: 'login', name: '', username: '', password: '', uris: [], totp: '', notes: '', favorite: false };
}

function newItem() {
  const s = state.session;
  const cid = s.collections().some(c => c.cid === state.view) ? state.view : s.pending ? s.personalCid : (s.collections().find(c => c.all)?.cid || s.personalCid);
  state.editing = { draft: blankItem(), cid, fromCid: null, isNew: true };
  state.sel = null;
  renderContent();
}

function currentItem() {
  if (!state.sel) return null;
  return state.session.allItems().find(i => i.id === state.sel.id && i.cid === state.sel.cid) || null;
}

function detailHead(title, ...right) {
  return h('header', { class: 'topbar' },
    iconBtn('back', 'Назад', () => { state.sel = null; state.editing = null; renderContent(); }, 'mobile-only'),
    h('h2', null, title), h('div', { class: 'spacer' }), ...right);
}

function row(label, value, actions = [], cls = '') {
  return h('div', { class: 'row ' + cls },
    h('div', { class: 'row-label' }, label),
    h('div', { class: 'row-value' }, value),
    h('div', { class: 'row-actions' }, actions));
}

function renderItem($d) {
  const it = currentItem();
  if (!it) { state.sel = null; return $d.append(h('div', { class: 'empty big' }, 'Запись не найдена')); }
  const s = state.session;
  const pwValue = h('span', { class: 'mono' + (state.reveal ? '' : ' masked') }, state.reveal ? it.password : '•'.repeat(Math.min(it.password?.length || 0, 16)));

  const card = h('div', { class: 'card' },
    it.username ? row('Логин', h('span', { class: 'mono' }, it.username), [iconBtn('copy', 'Копировать логин', () => copy(it.username, 'Логин скопирован'))]) : null,
    it.password ? row('Пароль', pwValue, [
      iconBtn(state.reveal ? 'eyeOff' : 'eye', state.reveal ? 'Скрыть' : 'Показать', () => { state.reveal = !state.reveal; renderContent(); }),
      iconBtn('copy', 'Копировать пароль', () => copy(it.password, 'Пароль скопирован')),
    ]) : null);

  if (it.totp) {
    const code = h('span', { class: 'mono totp' }, '…');
    const ring = h('span', { class: 'totp-left' });
    const tick = async () => {
      try {
        const t = await T.totpCode(it.totp);
        code.textContent = t.code.replace(/(\d{3})(\d+)/, '$1 $2');
        code.dataset.code = t.code;
        ring.textContent = t.left + ' с';
      } catch (e) { code.textContent = e.message; }
    };
    tick();
    timers.push(setInterval(tick, 1000));
    card.append(row('Код 2FA', h('span', null, code, ring), [iconBtn('copy', 'Копировать код', () => copy(code.dataset.code, 'Код скопирован'))]));
  }
  for (const uri of it.uris || []) {
    const href = T.safeUrl(uri);
    // Показываем нормализованный адрес: похожие буквы из других алфавитов видны как xn--…
    card.append(row('Сайт', h('span', { class: 'ellipsis', title: href || uri }, href || uri), [
      href ? h('a', { class: 'icon-btn', href, target: '_blank', rel: 'noopener noreferrer', title: 'Открыть сайт', 'aria-label': 'Открыть сайт' }, icon('external')) : null,
      iconBtn('copy', 'Копировать адрес', () => copy(uri, 'Адрес скопирован', false)),
    ]));
  }
  if (it.notes) card.append(row('Заметки', h('div', { class: 'notes' }, it.notes), [], 'block'));
  if (!card.childNodes.length) card.append(h('div', { class: 'muted pad' }, 'Пустая запись'));

  const who = s.org.members[it.updatedBy]?.name || (it.updatedBy === s.me.uid ? s.me.name : '');
  $d.append(
    detailHead('', iconBtn('star', it.favorite ? 'Убрать из избранного' : 'В избранное', e => run(async () => {
      await s.saveItem(it.cid, { ...it, favorite: !it.favorite });
      renderNav(); renderContent();
    }, e.currentTarget), it.favorite ? 'fav-on' : ''),
    iconBtn('edit', 'Изменить', () => { state.editing = { draft: structuredClone(it), cid: it.cid, fromCid: it.cid, isNew: false }; renderContent(); })),
    h('div', { class: 'detail-body' },
      h('div', { class: 'item-hero' }, avatar(it.name, 'large'),
        h('div', null, h('h2', null, it.name), h('span', { class: 'tag' }, icon(it.cid === s.personalCid ? 'user' : 'folder', 'small'), s.collectionName(it.cid)))),
      card,
      it.history?.length ? h('details', { class: 'history' },
        h('summary', null, 'Прошлые пароли (' + it.history.length + ')'),
        it.history.map(p => row(formatDate(p.changedAt), h('span', { class: 'mono masked' }, '•'.repeat(10)), [iconBtn('copy', 'Копировать', () => copy(p.password, 'Старый пароль скопирован'))]))) : null,
      h('p', { class: 'muted small' }, 'Изменено ' + formatDate(it.updatedAt) + (who ? ' · ' + who : ''))));
}

function renderEditor($d) {
  const s = state.session;
  const ed = state.editing;
  const d = ed.draft;
  const bind = (key, attrs = {}) => h('input', { value: d[key] || '', ...attrs, oninput: e => { d[key] = e.target.value; } });

  const pw = passwordInput({ value: d.password || '', autocomplete: 'new-password' });
  pw.input.addEventListener('input', () => { d.password = pw.input.value; });
  const gen = iconBtn('dice', 'Сгенерировать', () => {
    pw.input.value = d.password = T.generatePassword(LS.get('gen', {}));
    pw.input.type = 'text';
    pw.input.dispatchEvent(new Event('input'));
  });
  pw.el.append(gen);

  const uris = h('textarea', { rows: 2, placeholder: 'https://… (по одному на строку)', spellcheck: 'false', oninput: e => { d.uris = e.target.value.split('\n').map(x => x.trim()).filter(Boolean); } });
  uris.value = (d.uris || []).join('\n');
  const notes = h('textarea', { rows: 4, oninput: e => { d.notes = e.target.value; } });
  notes.value = d.notes || '';

  const colSel = h('select', { onchange: e => { ed.cid = e.target.value; } },
    s.collections().map(c => h('option', { value: c.cid, selected: c.cid === ed.cid }, c.name)));
  const typeSel = h('select', { onchange: e => { d.type = e.target.value; renderContent(); } },
    h('option', { value: 'login', selected: d.type === 'login' }, 'Логин и пароль'),
    h('option', { value: 'note', selected: d.type === 'note' }, 'Защищённая заметка'));

  const isLogin = d.type !== 'note';
  const form = h('form', {
    class: 'detail-body editor',
    onsubmit: e => {
      e.preventDefault();
      const btn = form.querySelector('button[type=submit]');
      run(async () => {
        d.name = (d.name || '').trim() || T.hostOf(d.uris?.[0] || '') || 'Без названия';
        if (d.totp) await T.totpCode(d.totp); // проверка, что секрет читается
        const saved = ed.isNew ? await s.saveItem(ed.cid, d) : await s.moveItem(d, ed.fromCid, ed.cid);
        state.editing = null;
        state.sel = { cid: saved.cid, id: saved.id };
        state.reveal = false;
        renderNav(); renderContent();
        toast('Сохранено');
      }, btn);
    },
  },
  h('div', { class: 'grid2' }, field('Тип', typeSel), field('Коллекция', colSel)),
  field('Название', bind('name', { placeholder: 'например, Instagram студии', maxlength: 200 })),
  isLogin ? field('Логин', bind('username', { autocomplete: 'off', spellcheck: 'false' })) : null,
  isLogin ? field('Пароль', [pw.el, strengthMeter(pw.input)]) : null,
  isLogin ? field('Сайты', uris) : null,
  isLogin ? field('Секрет 2FA', bind('totp', { placeholder: 'ключ или ссылка otpauth://', autocomplete: 'off', spellcheck: 'false' }), 'Тот же ключ, что вы вводите в Google Authenticator. Тогда коды будут видны здесь.') : null,
  field('Заметки', notes),
  h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: d.favorite, onchange: e => { d.favorite = e.target.checked; } }), 'В избранном'),
  h('div', { class: 'form-actions' },
    ed.isNew ? null : h('button', {
      type: 'button', class: 'btn danger ghost',
      onclick: e => run(async () => {
        if (!await confirmDialog('Удалить запись?', `«${d.name}» удалится у всех, у кого есть доступ к коллекции.`, 'Удалить', true)) return;
        await s.deleteItem(ed.fromCid, d.id);
        state.editing = null; state.sel = null;
        renderNav(); renderContent();
        toast('Удалено');
      }, e.currentTarget),
    }, icon('trash'), 'Удалить'),
    h('div', { class: 'spacer' }),
    h('button', { type: 'button', class: 'btn', onclick: () => { state.editing = null; renderContent(); } }, 'Отмена'),
    h('button', { type: 'submit', class: 'btn primary' }, 'Сохранить')));

  $d.append(detailHead(ed.isNew ? 'Новая запись' : 'Изменить'), form);
  form.querySelector('input')?.focus();
}

// ---------- команда ----------

const ROLE = { owner: 'Владелец', admin: 'Админ', member: 'Участник' };

async function renderTeam() {
  const s = state.session;
  const body = h('div', { class: 'page-body' });
  $content.append(h('section', { class: 'page' }, topBar('Команда «' + s.org.name + '»'), body));

  const teamCode = await V.teamCode(s.org);
  body.append(h('div', { class: 'card pad' },
    h('p', null, 'Код команды: ', h('strong', { class: 'code' }, teamCode)),
    s.isAdmin
      ? h('div', null,
        h('p', { class: 'muted small' }, 'Чтобы позвать человека, отправьте ему ссылку-приглашение. Он откроет её, придумает мастер-пароль, а вы примете заявку здесь.'),
        h('button', { class: 'btn primary', onclick: e => run(() => inviteDialog(), e.currentTarget) }, icon('plus'), 'Пригласить'))
      : h('p', { class: 'muted small' }, 'Приглашать новых участников могут владелец и админы.')));

  if (s.pending) {
    body.append(h('div', { class: 'banner' }, icon('clock'), h('span', null, 'Ваша заявка ждёт одобрения. Ваш код: ', h('strong', { class: 'code' }, await s.myCode()))));
    return;
  }

  // Заявки
  if (s.isAdmin) {
    const pending = await s.pendingUsers().catch(e => { toast(e.message, 'error'); return []; });
    pendingCount = pending.length;
    if (pending.length) {
      body.append(h('h3', null, 'Заявки'), h('div', { class: 'card' }, pending.map(p => h('div', { class: 'member' },
        avatar(p.name),
        h('div', { class: 'member-text' }, h('strong', null, p.name), h('span', { class: 'muted small' }, formatDate(p.createdAt))),
        p.valid ? h('div', { class: 'member-actions' },
          h('button', { class: 'btn primary small', onclick: () => approveDialog(p) }, 'Проверить и принять'),
          iconBtn('x', 'Отклонить', e => run(async () => {
            if (!await confirmDialog('Отклонить заявку?', `Заявка «${p.name}» будет удалена.`, 'Отклонить', true)) return;
            await s.reject(p.uid); renderContent();
          }, e.currentTarget)))
          : h('span', { class: 'tag error' }, 'повреждена')))));
    }
  }

  // Участники
  const members = Object.entries(s.org.members).sort(([, a], [, b]) => ['owner', 'admin', 'member'].indexOf(a.role) - ['owner', 'admin', 'member'].indexOf(b.role) || a.name.localeCompare(b.name, 'ru'));
  body.append(h('h3', null, 'Участники'), h('div', { class: 'card' }, members.map(([uid, m]) => {
    const canEdit = uid !== s.me.uid && m.role !== 'owner' && (s.isOwner || (s.isAdmin && m.role === 'member'));
    return h('div', { class: 'member' },
      avatar(m.name),
      h('div', { class: 'member-text' }, h('strong', null, m.name, uid === s.me.uid ? ' (вы)' : ''), h('span', { class: 'muted small' }, 'с ' + formatDate(m.addedAt))),
      h('div', { class: 'member-actions' },
        s.isOwner && m.role !== 'owner'
          ? h('select', {
            'aria-label': 'Роль',
            onchange: e => run(async () => { await s.setRole(uid, e.target.value); toast('Роль изменена'); renderNav(); renderContent(); }, e.target),
          }, h('option', { value: 'member', selected: m.role === 'member' }, 'Участник'), h('option', { value: 'admin', selected: m.role === 'admin' }, 'Админ'))
          : h('span', { class: 'tag' }, ROLE[m.role]),
        canEdit ? iconBtn('trash', 'Удалить из команды', e => run(async () => {
          if (!await confirmDialog('Удалить ' + m.name + '?', 'Доступ пропадёт сразу на всех его устройствах, а ключи его коллекций сменятся.', 'Удалить', true)) return;
          await s.removeMember(uid);
          await modal(m.name + ' удалён из команды', h('div', null,
            h('p', null, 'Сервер больше не пускает его, ключи его коллекций сменены.'),
            h('p', { class: 'warn' }, icon('shield'), 'Но пароли, которые он уже видел, он мог запомнить или скопировать. Смените важные пароли на самих сайтах.')),
          [{ label: 'Понятно', kind: 'primary', value: true }]);
          await s.loadAll(); renderNav(); renderContent();
        }, e.currentTarget)) : null));
  })));

  // Коллекции
  body.append(h('div', { class: 'section-head' }, h('h3', null, 'Коллекции'),
    s.isAdmin ? h('button', { class: 'btn small', onclick: () => collectionDialog() }, icon('plus'), 'Новая') : null));
  // Видны только коллекции, к которым есть ключ (у владельца и админов - все)
  body.append(h('div', { class: 'card' }, s.collections().filter(c => !c.personal).map(({ cid }) => {
    const col = s.org.collections[cid];
    const who = col.all ? 'Вся команда' : ['Админы', ...col.members.map(u => s.org.members[u]?.name).filter(Boolean)].join(', ');
    return h('div', { class: 'member' },
      h('span', { class: 'avatar icon-avatar' }, icon(col.all ? 'users' : 'folder')),
      h('div', { class: 'member-text' }, h('strong', null, s.collectionName(cid)), h('span', { class: 'muted small' }, who)),
      s.isAdmin ? h('div', { class: 'member-actions' }, iconBtn('edit', 'Настроить доступ', () => collectionDialog(cid))) : null);
  })));
  if (!s.isAdmin) body.append(h('p', { class: 'muted small' }, 'Менять состав команды и доступы могут владелец и админы.'));
}

async function inviteDialog() {
  if (state.demo) return toast('В демо-режиме приглашения не нужны: нажмите «Я новый участник» на экране входа');
  const { token, expires } = await state.storage.createInvite();
  const link = teamLink(token);
  await modal('Приглашение', h('div', null,
    h('p', null, 'Отправьте эту ссылку коллеге (лично, в мессенджере):'),
    h('div', { class: 'code-row' }, h('code', null, link), iconBtn('copy', 'Скопировать', () => copy(link, 'Ссылка скопирована', false))),
    h('p', { class: 'muted small' }, `Действует до ${formatDate(expires)}, по ней можно вступить до 25 человек. Каждую заявку вы всё равно принимаете вручную.`)),
  [{ label: 'Скопировать и закрыть', kind: 'primary', onClick: () => copy(link, 'Ссылка скопирована', false).then(() => true) }]);
}

async function approveDialog(p) {
  const s = state.session;
  const restricted = Object.entries(s.org.collections).filter(([, c]) => !c.all);
  const checks = restricted.map(([cid]) => ({ cid, el: h('input', { type: 'checkbox' }), name: s.collectionName(cid) }));
  const ok = await modal('Заявка: ' + p.name, h('div', null,
    h('p', null, 'Попросите человека назвать код с его экрана. Принимайте, только если коды совпадают:'),
    h('p', { class: 'code big-code' }, p.code),
    h('p', { class: 'muted small' }, 'Если код другой, кто-то мог подменить заявку. Тогда отклоните её.'),
    restricted.length ? h('div', null, h('p', null, 'Доступ к коллекциям (к «для всех» он будет и так):'),
      checks.map(c => h('label', { class: 'check' }, c.el, c.name))) : null),
  [
    { label: 'Отмена', value: false },
    { label: 'Коды совпадают, принять', kind: 'primary', onClick: () => s.approve(p.uid, p.code, checks.filter(c => c.el.checked).map(c => c.cid)).then(() => true) },
  ]);
  if (ok) {
    toast(p.name + ' в команде');
    await s.loadAll();
    renderNav(); renderContent();
  }
}

async function collectionDialog(cid) {
  const s = state.session;
  const col = cid ? s.org.collections[cid] : { all: false, members: [] };
  const colName = cid ? s.collectionName(cid) : '';
  const name = h('input', { value: colName, maxlength: 60, required: true });
  const all = h('input', { type: 'checkbox', checked: col.all });
  const people = Object.entries(s.org.members).filter(([, m]) => m.role === 'member');
  const checks = people.map(([uid, m]) => ({ uid, el: h('input', { type: 'checkbox', checked: col.members.includes(uid) }), name: m.name }));
  const list = h('div', { class: 'checks' },
    h('p', { class: 'muted small' }, 'Владелец и админы видят все коллекции. Кому из участников дать доступ:'),
    checks.length ? checks.map(c => h('label', { class: 'check' }, c.el, c.name)) : h('p', { class: 'muted small' }, 'Обычных участников пока нет.'));
  const sync = () => { list.hidden = all.checked; };
  all.addEventListener('change', sync);
  sync();

  const actions = [{ label: 'Отмена', value: false }];
  if (cid) actions.unshift({
    label: 'Удалить', kind: 'danger ghost', onClick: async () => {
      const n = Object.keys(s.vaults.get(cid)?.items || {}).length;
      if (!await confirmDialog('Удалить коллекцию «' + colName + '»?', n ? `Вместе с ней удалятся ${n} записей у всех участников.` : 'Коллекция пустая.', 'Удалить', true)) return false;
      await s.deleteCollection(cid);
      if (state.view === cid) state.view = 'all';
      return true;
    },
  });
  actions.push({
    label: cid ? 'Сохранить' : 'Создать', kind: 'primary', onClick: async () => {
      const n = name.value.trim();
      if (!n) throw new Error('Введите название');
      const members = checks.filter(c => c.el.checked).map(c => c.uid);
      if (cid) await s.updateCollection(cid, { name: n === colName ? null : n, all: all.checked, members });
      else await s.createCollection(n, all.checked, members);
      return true;
    },
  });
  const ok = await modal(cid ? 'Коллекция' : 'Новая коллекция', h('div', null,
    field('Название', name),
    h('label', { class: 'check' }, all, 'Для всей команды'),
    list,
    cid ? h('p', { class: 'muted small' }, 'Если забрать у кого-то доступ, ключ коллекции сменится автоматически.') : null), actions);
  if (ok) {
    await s.loadAll();
    renderNav(); renderContent();
  }
}

// ---------- генератор ----------

function renderGenerator() {
  const opts = { length: 20, lower: true, upper: true, digits: true, symbols: true, ...LS.get('gen', {}) };
  const out = h('div', { class: 'gen-out mono' });
  const len = h('input', { type: 'range', min: 8, max: 64, value: opts.length });
  const lenLabel = h('span', { class: 'mono' });
  const make = () => {
    opts.length = Number(len.value);
    lenLabel.textContent = opts.length;
    LS.set('gen', opts);
    out.textContent = T.generatePassword(opts);
    const st = T.strength(out.textContent);
    meter.textContent = st.label + ' · ~' + st.bits + ' бит';
  };
  const meter = h('div', { class: 'muted small' });
  const toggle = (key, label) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: opts[key], onchange: e => { opts[key] = e.target.checked; make(); } }), label);
  len.addEventListener('input', make);
  $content.append(h('section', { class: 'page' }, topBar('Генератор паролей'), h('div', { class: 'page-body narrow' },
    h('div', { class: 'card pad' },
      out, meter,
      h('div', { class: 'gen-actions' },
        h('button', { class: 'btn', onclick: make }, icon('dice'), 'Ещё'),
        h('button', { class: 'btn primary', onclick: () => copy(out.textContent, 'Пароль скопирован') }, icon('copy'), 'Копировать'))),
    h('div', { class: 'card pad' },
      h('div', { class: 'range' }, h('span', null, 'Длина'), len, lenLabel),
      toggle('lower', 'Строчные a-z'), toggle('upper', 'Заглавные A-Z'), toggle('digits', 'Цифры'), toggle('symbols', 'Символы !@#…'),
      h('p', { class: 'muted small' }, 'Похожие символы (l, I, O, 0, 1) исключены. Эти же настройки используются кнопкой генерации в записи.')))));
  make();
}

// ---------- настройки ----------

async function renderSettings() {
  const s = state.session;
  const lockSel = h('select', { onchange: e => { LS.set('lockMin', Number(e.target.value)); toast('Сохранено'); } },
    [[1, '1 минуту'], [5, '5 минут'], [15, '15 минут'], [60, '1 час'], [240, '4 часа']].map(([v, l]) => h('option', { value: v, selected: lockMinutes() === v }, l)));

  const importFile = h('input', { type: 'file', accept: '.csv,text/csv', class: 'visually-hidden' });
  const importCol = h('select', null, s.collections().map(c => h('option', { value: c.cid }, c.name)));
  importFile.addEventListener('change', () => run(async () => {
    const f = importFile.files[0];
    if (!f) return;
    const items = T.importCsv(await f.text());
    importFile.value = '';
    if (!items.length) throw new Error('В файле не нашлось записей');
    if (!await confirmDialog('Импорт', `Добавить ${items.length} записей в «${s.collectionName(importCol.value)}»?`, 'Добавить')) return;
    await s.addItems(importCol.value, items);
    renderNav();
    await modal('Готово', h('div', null,
      h('p', null, `Импортировано записей: ${items.length}.`),
      h('p', { class: 'warn' }, icon('shield'), 'Теперь удалите CSV-файл с компьютера и очистите корзину: в нём пароли лежат открытым текстом.')),
    [{ label: 'Понятно', kind: 'primary', value: true }]);
  }));

  $content.append(h('section', { class: 'page' }, topBar('Настройки'), h('div', { class: 'page-body narrow' },
    h('h3', null, 'Профиль'),
    h('div', { class: 'card pad' },
      h('p', null, h('strong', null, s.me.name), ' · ', ROLE[s.role] || 'Ждёт одобрения'),
      h('p', null, 'Ваш код: ', h('strong', { class: 'code' }, await s.myCode())),
      h('p', null, 'Код команды: ', h('strong', { class: 'code' }, await V.teamCode(s.org)))),

    h('h3', null, 'Безопасность'),
    h('div', { class: 'card pad' },
      field('Блокировать при бездействии через', lockSel),
      h('button', { class: 'btn', onclick: () => changePasswordDialog() }, icon('key'), 'Сменить мастер-пароль')),

    h('h3', null, 'Импорт и экспорт'),
    h('div', { class: 'card pad' },
      h('p', { class: 'muted small' }, 'Импорт из CSV: Bitwarden, Chrome, Edge, Яндекс Браузер, Firefox и другие.'),
      field('В коллекцию', importCol),
      h('div', { class: 'gen-actions' },
        h('button', { class: 'btn', onclick: () => importFile.click() }, icon('upload'), 'Импорт CSV'),
        h('button', { class: 'btn', onclick: () => exportDialog() }, icon('download'), 'Экспорт')),
      importFile),

    h('h3', null, 'Это устройство'),
    h('div', { class: 'card pad' },
      state.demo ? h('p', { class: 'muted small' }, 'Демо-режим: данные живут только в этой вкладке.') : h('div', null,
        h('p', { class: 'muted small' }, 'Вход с другого устройства: откройте там эту ссылку и войдите своим мастер-паролем. Ссылка не даёт доступа к паролям без мастер-пароля, но не публикуйте её.'),
        h('div', { class: 'gen-actions' },
          h('button', { class: 'btn', onclick: () => copy(teamLink(), 'Ссылка скопирована', false) }, icon('copy'), 'Ссылка для входа'),
          h('button', { class: 'btn danger ghost', onclick: e => run(async () => {
            if (!await confirmDialog('Забыть команду на этом устройстве?', 'Сохранённые на устройстве зашифрованные данные удалятся. Чтобы войти снова, понадобится ссылка команды. Данные на сервере останутся.', 'Забыть', true)) return;
            forgetDevice();
            lock();
          }, e.currentTarget) }, 'Забыть на этом устройстве')))),

    h('p', { class: 'muted small center' }, 'Ключница ' + APP_VERSION + ' · шифрование AES-256-GCM, Argon2id, X25519, Ed25519'))));
}

async function changePasswordDialog() {
  const s = state.session;
  const cur = passwordInput({ autocomplete: 'current-password' });
  const mp = masterPasswordFields();
  await modal('Смена мастер-пароля', h('div', null, field('Текущий мастер-пароль', cur.el), ...mp.els), [
    { label: 'Отмена', value: false },
    {
      label: 'Сменить', kind: 'primary', onClick: async () => {
        const next = mp.value();
        await s.checkPassword(cur.input.value);
        await s.changePassword(next);
        toast('Мастер-пароль изменён');
        return true;
      },
    },
  ]);
}

async function exportDialog() {
  const s = state.session;
  const cols = s.collections().map(c => ({ ...c, el: h('input', { type: 'checkbox', checked: true }) }));
  const pw = passwordInput({ autocomplete: 'current-password' });
  await modal('Экспорт', h('div', null,
    h('p', { class: 'warn' }, icon('shield'), 'Файл будет НЕ зашифрован: в нём все пароли открытым текстом. Храните его только на флешке или в другом менеджере и удалите после использования.'),
    cols.map(c => h('label', { class: 'check' }, c.el, c.name)),
    field('Мастер-пароль для подтверждения', pw.el)),
  [
    { label: 'Отмена', value: false },
    {
      label: 'Скачать JSON', kind: 'danger', onClick: async () => {
        await s.checkPassword(pw.input.value);
        const chosen = new Set(cols.filter(c => c.el.checked).map(c => c.cid));
        const items = s.allItems().filter(i => chosen.has(i.cid)).map(i => ({ ...i, collection: s.collectionName(i.cid), cid: undefined, updatedBy: undefined }));
        const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), items }, null, 2)], { type: 'application/json' });
        const a = h('a', { href: URL.createObjectURL(blob), download: 'klyuchnitsa-export.json' });
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
        return true;
      },
    },
  ]);
}

// ---------- автоблокировка и фоновая синхронизация ----------

function lockMinutes() { return LS.get('lockMin', 15); }

let lastActive = Date.now();
for (const ev of ['pointerdown', 'keydown', 'touchstart']) addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true, capture: true });

setInterval(() => {
  if (!state.session) return;
  if (Date.now() - lastActive > lockMinutes() * 60000) return lock();
  if (document.visibilityState === 'visible' && !state.editing && Date.now() - state.syncedAt > 60000) sync();
}, 10000);

// Ссылку команды вставили в уже открытую вкладку - страница не перезагружается, разбираем сами
addEventListener('hashchange', () => {
  if (/(^#|&)(t|setup)=/.test(location.hash)) lock();
});

document.addEventListener('visibilitychange', () => {
  if (!state.session || document.visibilityState !== 'visible') return;
  if (Date.now() - lastActive > lockMinutes() * 60000) return lock();
  if (Date.now() - state.syncedAt > 20000) sync();
});

start();
