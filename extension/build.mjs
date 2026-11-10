// Сборка расширения: node extension/build.mjs  ->  extension/dist/chrome и extension/dist/firefox
// Общий код (шифрование, сервер, хранилище) берётся из ../js без копий в репозитории.
import { cpSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const { API_URL, APP_VERSION } = await import(join(root, 'js/config.js'));
const argonSri = /integrity="([^"]+)"/.exec(readFileSync(join(root, 'index.html'), 'utf8'))[1];

const SHARED = ['crypto.js', 'vault.js', 'storage.js', 'tools.js', 'config.js'];
const OWN = ['popup.html', 'popup.css', 'popup.js', 'background.js', 'match.js', 'fill.js', 'capture.js'];

const base = {
  manifest_version: 3,
  name: 'Ключница',
  version: APP_VERSION,
  description: 'Пароли команды из Ключницы: поиск, копирование, 2FA и подстановка на сайт по клику',
  icons: { 48: 'icons/icon-192.png', 128: 'icons/icon-192.png' },
  action: { default_popup: 'popup.html', default_title: 'Ключница', default_icon: { 48: 'icons/icon-192.png' } },
  permissions: ['storage', 'activeTab', 'scripting', 'alarms'],
  host_permissions: [API_URL + '/*'],
  content_security_policy: {
    extension_pages: `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src ${API_URL}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  },
  commands: { _execute_action: { suggested_key: { default: 'Ctrl+Shift+K', mac: 'Command+Shift+K' }, description: 'Открыть Ключницу' },
    fill: { suggested_key: { default: 'Ctrl+Shift+L', mac: 'Command+Shift+L' }, description: 'Подставить логин и пароль' },
  },
  content_scripts: [{ matches: ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'], js: ['capture.js'], run_at: 'document_idle', all_frames: false }],
};

const variants = {
  chrome: { background: { service_worker: 'background.js', type: 'module' } },
  firefox: {
    background: { scripts: ['background.js'], type: 'module' },
    browser_specific_settings: { gecko: { id: 'keybox@klyuchnitsa.local', strict_min_version: '115.0' } },
  },
};

rmSync(join(here, 'dist'), { recursive: true, force: true });
for (const [name, extra] of Object.entries(variants)) {
  const out = join(here, 'dist', name);
  mkdirSync(join(out, 'lib/js'), { recursive: true });
  mkdirSync(join(out, 'lib/vendor'), { recursive: true });
  for (const f of SHARED) cpSync(join(root, 'js', f), join(out, 'lib/js', f));
  cpSync(join(root, 'vendor/argon2.umd.min.js'), join(out, 'lib/vendor/argon2.umd.min.js'));
  cpSync(join(root, 'icons'), join(out, 'icons'), { recursive: true });
  for (const f of OWN) {
    let text = readFileSync(join(here, f), 'utf8').replaceAll('__ARGON_SRI__', argonSri);
    writeFileSync(join(out, f), text);
  }
  writeFileSync(join(out, 'manifest.json'), JSON.stringify({ ...base, ...extra }, null, 2));
  console.log('собрано', join('extension/dist', name));
}
