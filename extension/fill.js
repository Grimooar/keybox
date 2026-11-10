// Подстановка логина/пароля/2FA в страницу. Вызывается через scripting.executeScript({func: fillForm}),
// поэтому функция САМОДОСТАТОЧНА: никаких импортов и внешних переменных, хелперы вложены внутрь.
export function fillForm({ origin, username, password, totp }) {
  if (location.origin !== origin) return { ok: false, user: false, pass: false, otp: false, reason: 'origin' };

  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const vw = window.innerWidth || document.documentElement.clientWidth;
  const vh = window.innerHeight || document.documentElement.clientHeight;

  const usable = el => {
    if (!el || el.disabled || el.readOnly || el.hidden) return false;
    const t = (el.type || '').toLowerCase();
    if (t === 'hidden') return false;
    if (!el.offsetWidth || !el.offsetHeight) return false;
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
  const inputs = root => Array.from(root.querySelectorAll('input')).filter(usable);
  const typeOf = el => (el.getAttribute('type') || 'text').toLowerCase();
  const OTP_RE = /otp|2fa|totp|code|код/i;
  const isOtp = el => {
    if ((el.autocomplete || '').toLowerCase().includes('one-time-code')) return true;
    return ['text', 'tel', 'number'].includes(typeOf(el)) && OTP_RE.test([el.name, el.id, el.placeholder].join(' '));
  };
  const isUser = el => {
    const ac = (el.autocomplete || '').toLowerCase();
    if (ac.includes('username') || ac.includes('email')) return true;
    return ['text', 'email', 'tel'].includes(typeOf(el)) && !isOtp(el);
  };
  const put = (el, v) => {
    el.focus();
    setter.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };

  const res = { ok: false, user: false, pass: false, otp: false };
  const all = inputs(document);
  const pwd = all.find(el => typeOf(el) === 'password');
  const scope = pwd && pwd.form ? inputs(pwd.form) : all;

  if (pwd && password) { put(pwd, password); res.pass = true; }

  if (username) {
    let target = null;
    if (pwd) {
      const idx = scope.indexOf(pwd);
      for (let i = idx - 1; i >= 0; i--) if (isUser(scope[i])) { target = scope[i]; break; }
    } else {
      target = all.find(isUser) || null;
    }
    if (target) { put(target, username); res.user = true; }
  }

  if (totp) {
    const o = all.find(isOtp);
    if (o) { put(o, totp); res.otp = true; }
  }

  res.ok = res.user || res.pass || res.otp;
  if (!res.ok) res.reason = 'no-fields';
  return res;
}
