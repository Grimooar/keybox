// Страница получателя: открывает секрет только по нажатию (превью ссылок в мессенджерах не сжигают просмотр)
import { API_URL } from './config.js';
import { parseFragment, fetchSend } from './send.js';

const $ = id => document.getElementById(id);
const link = parseFragment(location.hash);
// Ключ убираем из адресной строки и истории
history.replaceState(null, '', location.pathname);

function show(id) { for (const s of ['intro', 'result', 'gone', 'error']) $(s).hidden = s !== id; }

if (!link) show('gone');
else show('intro');

$('reveal').addEventListener('click', async () => {
  $('reveal').disabled = true;
  try {
    const res = await fetchSend(link.id, link.key, { apiUrl: API_URL });
    if (!res) return show('gone');
    $('secret').textContent = res.text;
    $('left').textContent = res.viewsLeft > 0 ? 'Осталось открытий: ' + res.viewsLeft : 'Это было последнее открытие - ссылка больше не работает.';
    show('result');
  } catch (e) {
    $('errmsg').textContent = /расшифр/i.test(e.message) ? 'Ссылка повреждена: не удалось расшифровать.' : e.message;
    show('error');
  }
});

$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('secret').textContent); $('copy').textContent = 'Скопировано'; } catch { $('copy').textContent = 'Не удалось скопировать'; }
});
