// Мелкие помощники интерфейса. Всё строится через DOM и textContent,
// без innerHTML: названия записей пишут другие участники, им нельзя доверять как HTML.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
}

const ICONS = {
  lock: 'M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4',
  copy: 'M9 9h11v11H9z M5 15H4V4h11v1',
  eye: 'M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  eyeOff: 'M3 3l18 18 M10.6 10.6a2 2 0 0 0 2.8 2.8 M9.9 5.2A10 10 0 0 1 12 5c7 0 11 7 11 7a18 18 0 0 1-3.2 4.2 M6.6 6.6C3.4 8.4 1 12 1 12s4 7 11 7a10 10 0 0 0 5.4-1.6',
  plus: 'M12 5v14 M5 12h14',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M21 21l-5-5',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2 M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z M23 21v-2a4 4 0 0 0-3-3.9 M16 3.1a4 4 0 0 1 0 7.8',
  sliders: 'M4 21v-7 M4 10V3 M12 21v-9 M12 8V3 M20 21v-5 M20 12V3 M1 14h6 M9 8h6 M17 16h6',
  refresh: 'M23 4v6h-6 M1 20v-6h6 M3.5 9a9 9 0 0 1 14.8-3.4L23 10 M1 14l4.7 4.4A9 9 0 0 0 20.5 15',
  star: 'M12 2l3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1z',
  trash: 'M3 6h18 M8 6V4h8v2 M19 6l-1 14H6L5 6',
  external: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6 M15 3h6v6 M10 14L21 3',
  dice: 'M21 12a9 9 0 1 1-3-6.7L21 8 M21 3v5h-5',
  folder: 'M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z',
  grid: 'M3 3h7v7H3z M14 3h7v7h-7z M14 14h7v7h-7z M3 14h7v7H3z',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2 M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
  key: 'M15.5 7.5l3 3L22 7l-3-3 M11.4 11.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8z M11.4 11.6L19 4',
  x: 'M18 6L6 18 M6 6l12 12',
  menu: 'M3 6h18 M3 12h18 M3 18h18',
  back: 'M15 18l-6-6 6-6',
  edit: 'M12 20h9 M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4 M7 10l5 5 5-5 M12 15V3',
  upload: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4 M17 8l-5-5-5 5 M12 3v12',
  clock: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M12 6v6l4 2',
  note: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8 M8 17h8',
  check: 'M20 6L9 17l-5-5',
};

export function icon(name, cls = '') {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'icon ' + cls);
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(NS, 'path');
  p.setAttribute('d', ICONS[name] || '');
  svg.append(p);
  return svg;
}

export function iconBtn(name, title, onclick, cls = '') {
  return h('button', { class: 'icon-btn ' + cls, type: 'button', title, 'aria-label': title, onclick }, icon(name));
}

export function clear(el) {
  while (el.firstChild) el.firstChild.remove();
  return el;
}

// ---------- уведомления ----------

export function toast(text, kind = 'info') {
  const box = document.getElementById('toasts');
  const t = h('div', { class: 'toast ' + kind, role: kind === 'error' ? 'alert' : 'status' }, text);
  box.append(t);
  while (box.children.length > 3) box.firstChild.remove();
  setTimeout(() => t.classList.add('hide'), kind === 'error' ? 6000 : 2800);
  setTimeout(() => t.remove(), kind === 'error' ? 6500 : 3300);
}

// ---------- модальные окна ----------

export function modal(title, body, actions = []) {
  return new Promise(resolve => {
    const prevFocus = document.activeElement;
    const close = v => {
      wrap.remove();
      document.removeEventListener('keydown', onKey);
      prevFocus?.focus?.();
      resolve(v);
    };
    const onKey = e => { if (e.key === 'Escape') close(null); };
    const dlg = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'modal-head' }, h('h2', null, title), iconBtn('x', 'Закрыть', () => close(null))),
      h('div', { class: 'modal-body' }, body),
      actions.length ? h('div', { class: 'modal-actions' }, actions.map(a =>
        h('button', {
          class: 'btn ' + (a.kind || ''), type: 'button',
          onclick: async e => {
            if (!a.onClick) return close(a.value);
            const btn = e.currentTarget;
            btn.disabled = true;
            try {
              const v = await a.onClick();
              if (v !== false) close(v === undefined ? a.value : v);
            } catch (err) {
              toast(err.message, 'error');
            } finally {
              btn.disabled = false;
            }
          },
        }, a.label))) : null);
    const wrap = h('div', { class: 'modal-wrap', onmousedown: e => { if (e.target === wrap) close(null); } }, dlg);
    document.body.append(wrap);
    document.addEventListener('keydown', onKey);
    (dlg.querySelector('input, select, textarea') || dlg.querySelector('.modal-actions .btn:last-child'))?.focus();
  });
}

export function confirmDialog(title, text, okLabel = 'Да', danger = false) {
  return modal(title, h('p', null, text), [
    { label: 'Отмена', value: false },
    { label: okLabel, kind: danger ? 'danger' : 'primary', value: true },
  ]).then(v => v === true);
}

// ---------- поля ----------

export function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', { class: 'field-label' }, label), input, hint ? h('span', { class: 'field-hint' }, hint) : null);
}

export function formatDate(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleString('ru-RU', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// Цвет аватарки по названию
export function avatar(name, cls = '') {
  let hsh = 0;
  for (const ch of name || '?') hsh = (hsh * 31 + ch.codePointAt(0)) >>> 0;
  const el = h('span', { class: 'avatar ' + cls, 'aria-hidden': 'true' }, [...(name || '?').trim()][0]?.toUpperCase() || '?');
  el.style.setProperty('--hue', String(hsh % 360));
  return el;
}
