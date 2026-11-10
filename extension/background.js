// Фон расширения: автоблокировка, приём захваченного пароля и горячая клавиша подстановки.
// Ключи живут в storage.session (память браузера, на диск не пишутся, скриптам страниц недоступны)
// и стираются по таймеру, при запуске браузера и при выходе.
import { fillable } from './match.js';

const ext = globalThis.browser || globalThis.chrome;
const PENDING_MS = 2 * 60 * 1000;

const wipe = () => ext.storage.session.remove(['unlocked', 'pending', 'autofill']);
const clearPending = async () => {
  await ext.storage.session.remove('pending');
  try { await ext.action.setBadgeText({ text: '' }); } catch {}
};

ext.alarms.onAlarm.addListener(a => {
  if (a.name === 'kb-lock') wipe();
  if (a.name === 'kb-pending') clearPending();
});
ext.runtime.onStartup.addListener(wipe);
ext.runtime.onInstalled.addListener(wipe);

const okStr = (v, min = 0) => typeof v === 'string' && v.length >= min && v.length <= 1000;
const originOf = u => { try { return new URL(u).origin; } catch { return null; } };

async function capture(msg, sender) {
  if (sender.id !== ext.runtime.id) return;
  const url = sender.tab && sender.tab.url;
  if (!url || !fillable(url) || originOf(url) !== msg.origin) return;
  if (!okStr(msg.origin, 1) || !okStr(msg.username) || !okStr(msg.password, 1)) return;
  const { unlocked } = await ext.storage.session.get('unlocked');
  if (!unlocked) return; // заблокирована — пароль не держим
  await ext.storage.session.set({
    pending: { origin: msg.origin, host: new URL(url).host, username: msg.username, password: msg.password, isNew: msg.isNew === true, at: Date.now() },
  });
  try {
    await ext.action.setBadgeText({ text: '+' });
    await ext.action.setBadgeBackgroundColor({ color: '#2e7d32' });
  } catch {}
  ext.alarms.create('kb-pending', { when: Date.now() + PENDING_MS });
}

ext.runtime.onMessage.addListener((msg, sender) => {
  if (msg && msg.type === 'kb-capture') capture(msg, sender).catch(() => {});
  return false;
});

// Вкладку берём из аргумента, а openPopup вызываем в том же такте: после await Firefox теряет «жест пользователя»
ext.commands.onCommand.addListener((cmd, tab) => {
  if (cmd !== 'fill' || !tab) return;
  ext.storage.session.set({ autofill: { tabId: tab.id, at: Date.now() } });
  try { Promise.resolve(ext.action.openPopup()).catch(() => {}); } catch { /* старый браузер: останется флаг */ }
});
