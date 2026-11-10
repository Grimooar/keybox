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
})();
