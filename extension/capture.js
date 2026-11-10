// Захват логина/пароля при отправке формы входа/регистрации. Content script, только верхний фрейм.
// Самодостаточен (без импортов). Страницу не меняет, UI не рисует; пароль живёт только внутри вызова.
(() => {
  const ext = globalThis.browser || globalThis.chrome;
  if (!ext || !ext.runtime || window.top !== window) return;
  let last = 0;

  // та же проверка видимости, что в fill.js (отсекает honeypot-поля)
  const usable = el => {
    if (!el || el.disabled || el.readOnly || el.hidden) return false;
    if ((el.type || '').toLowerCase() === 'hidden') return false;
    if (!el.offsetWidth || !el.offsetHeight) return false;
    const vw = window.innerWidth || document.documentElement.clientWidth;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8) return false;
    if (r.right < -10 || r.bottom < -10 || r.left > vw + 10 || r.top > vh + 2000) return false;
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      if (n.getAttribute('aria-hidden') === 'true' || n.hidden) return false;
      const s = getComputedStyle(n);
      if (s.display === 'none' || s.visibility === 'hidden' || s.visibility === 'collapse' || parseFloat(s.opacity) === 0) return false;
    }
    return true;
  };
  const typeOf = el => (el.getAttribute('type') || 'text').toLowerCase();
  const isPass = el => el instanceof HTMLInputElement && typeOf(el) === 'password';
  const isUser = el => {
    const ac = (el.autocomplete || '').toLowerCase();
    if (ac.includes('username') || ac.includes('email')) return true;
    if (ac.includes('one-time-code')) return false;
    return ['text', 'email', 'tel'].includes(typeOf(el));
  };

  const grab = root => {
    if (Date.now() - last < 3000) return;
    const scope = root && root.querySelectorAll ? root : document;
    const all = Array.from(scope.querySelectorAll('input')).filter(usable);
    const passes = all.filter(el => isPass(el) && el.value);
    if (!passes.length) return;
    const pw = passes[0];
    const idx = all.indexOf(pw);
    let user = null;
    for (let i = idx - 1; i >= 0; i--) if (!isPass(all[i]) && isUser(all[i]) && all[i].value) { user = all[i]; break; }
    const isNew = passes.some(el => (el.autocomplete || '').toLowerCase().includes('new-password'))
      || all.filter(isPass).length >= 2;
    last = Date.now();
    try {
      ext.runtime.sendMessage({
        type: 'kb-capture', origin: location.origin,
        username: user ? String(user.value) : '', password: String(pw.value), isNew,
      }).catch?.(() => {});
    } catch { /* расширение перезагружено */ }
  };

  const formOf = el => (el && el.closest && el.closest('form')) || null;
  const scopeOf = el => {
    const f = formOf(el);
    if (f) return f;
    // SPA без <form>: ближайший предок, где есть поле пароля
    for (let n = el && el.parentElement; n; n = n.parentElement) if (n.querySelector('input[type=password]')) return n;
    return document;
  };

  document.addEventListener('submit', e => grab(e.target), true);
  document.addEventListener('click', e => {
    const b = e.target && e.target.closest && e.target.closest('button, input[type=submit], [role=button]');
    if (!b) return;
    const t = (b.getAttribute('type') || (b.tagName === 'BUTTON' ? 'submit' : '')).toLowerCase();
    if (!['submit', 'button'].includes(t) && b.getAttribute('role') !== 'button') return;
    const s = scopeOf(b);
    if (s.querySelector && s.querySelector('input[type=password]')) grab(s);
  }, true);
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.isTrusted && isPass(e.target)) grab(scopeOf(e.target));
  }, true);

  // Кнопка «🔑» в полях логина и пароля. Секреты в страницу не попадают: клик только просит фон
  // открыть окно Ключницы, где пользователь сам выбирает запись. Закрытый shadow DOM скрывает кнопку от скриптов сайта.
  const host = document.createElement('div');
  host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;display:none';
  const root = host.attachShadow({ mode: 'closed' });
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = '\u{1F511}';
  btn.title = 'Ключница: подставить логин и пароль';
  btn.style.cssText = 'all:initial;cursor:pointer;font:14px/22px sans-serif;width:24px;height:24px;text-align:center;background:#1c2230;color:#fff;border:1px solid #3a4258;border-radius:6px;box-shadow:0 1px 4px #0006';
  root.append(btn);
  let field = null;
  const hide = () => { host.style.display = 'none'; field = null; };
  const place = () => {
    if (!field || !field.isConnected || !usable(field)) return hide();
    const r = field.getBoundingClientRect();
    host.style.left = Math.max(0, Math.min(r.right - 28, window.innerWidth - 28)) + 'px';
    host.style.top = Math.max(0, r.top + (r.height - 24) / 2) + 'px';
    host.style.display = 'block';
  };
  const loginField = el => el instanceof HTMLInputElement && usable(el) && (isPass(el) || (isUser(el) && scopeOf(el).querySelector && scopeOf(el).querySelector('input[type=password]')));
  document.addEventListener('focusin', e => {
    if (!loginField(e.target)) return;
    field = e.target;
    if (!host.isConnected) (document.body || document.documentElement).append(host);
    place();
  }, true);
  document.addEventListener('focusout', () => setTimeout(() => { if (!host.matches(':hover')) hide(); }, 200), true);
  addEventListener('scroll', place, true);
  addEventListener('resize', place);
  btn.addEventListener('click', e => {
    if (!e.isTrusted) return;
    try { ext.runtime.sendMessage({ type: 'kb-open' }).catch?.(() => {}); } catch { /* расширение перезагружено */ }
  });
})();
