// Тесты расширения: node tests/ext.test.mjs
import assert from 'node:assert/strict';
import { matches, fillable, itemMatches } from '../extension/match.js';
import { fillForm } from '../extension/fill.js';

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ok  ', name); }
  catch (e) { console.log('  FAIL', name, '\n      ', e.stack); process.exitCode = 1; }
}

console.log('match.js');
test('точное совпадение', () => assert.ok(matches('https://github.com/login', 'https://github.com/x?y=1')));
test('uri без схемы', () => assert.ok(matches('github.com', 'https://github.com/')));
test('www. не в счёт', () => {
  assert.ok(matches('https://www.example.com', 'https://example.com'));
  assert.ok(matches('example.com', 'https://www.example.com'));
});
test('порт должен совпадать', () => {
  assert.ok(matches('https://example.com:8443', 'https://example.com:8443/a'));
  assert.ok(!matches('https://example.com', 'https://example.com:8443'));
  assert.ok(!matches('https://example.com:8443', 'https://example.com'));
});
test('http запрещён, кроме localhost', () => {
  assert.ok(!matches('http://example.com', 'http://example.com'));
  assert.ok(!fillable('http://example.com'));
  assert.ok(matches('http://localhost:3000', 'http://localhost:3000/'));
  assert.ok(fillable('http://127.0.0.1:8080'));
});
test('поддомен не совпадает', () => {
  assert.ok(!matches('github.io', 'https://evil.github.io'));
  assert.ok(!matches('evil.github.io', 'https://github.io'));
  assert.ok(!matches('example.com', 'https://login.example.com'));
  assert.ok(!matches('login.example.com', 'https://example.com'));
  assert.ok(!matches('example.com', 'https://example.com.evil.net'));
});
test('опасные схемы отвергаются', () => {
  assert.ok(!matches('javascript:alert(1)', 'https://example.com'));
  assert.ok(!matches('data:text/html,x', 'https://example.com'));
  assert.ok(!matches('https://example.com', 'javascript:alert(1)'));
  assert.ok(!matches('https://example.com', 'data:text/html,x'));
  assert.ok(!fillable('chrome://settings'));
});
test('пустые uris', () => {
  assert.ok(!itemMatches({ uris: [] }, 'https://example.com'));
  assert.ok(!itemMatches({}, 'https://example.com'));
  assert.ok(!matches('', 'https://example.com'));
  assert.ok(!matches(undefined, undefined));
  assert.ok(itemMatches({ uris: ['a.com', 'example.com'] }, 'https://example.com'));
});

console.log('fill.js');
test('самодостаточна: парсится и без внешних имён', () => {
  const src = String(fillForm);
  const f = new Function('return ' + src)();
  assert.equal(typeof f, 'function');
  assert.ok(!/\b(import|require)\b/.test(src));
  assert.ok(!/console\./.test(src));
});
test('чужой origin: ничего не трогает', () => {
  globalThis.location = { origin: 'https://evil.com' };
  let touched = false;
  globalThis.document = new Proxy({}, { get() { touched = true; return undefined; } });
  const r = fillForm({ origin: 'https://example.com', username: 'u', password: 'p', totp: '1' });
  delete globalThis.location; delete globalThis.document;
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'origin');
  assert.equal(touched, false);
});

console.log('capture.js + build');
{
  const { readFileSync } = await import('node:fs');
  const { execFileSync } = await import('node:child_process');
  const ext = new URL('../extension/', import.meta.url);
  test('capture.js самодостаточен и без console', () => {
    const src = readFileSync(new URL('capture.js', ext), 'utf8');
    new Function(src);
    assert.ok(!/\b(import|require)\b/.test(src));
    assert.ok(!/console\./.test(src));
    assert.ok(src.includes("'kb-capture'"));
  });
  execFileSync(process.execPath, [new URL('build.mjs', ext).pathname], { stdio: 'ignore' });
  for (const b of ['chrome', 'firefox']) test(`manifest ${b}`, () => {
    const m = JSON.parse(readFileSync(new URL(`dist/${b}/manifest.json`, ext), 'utf8'));
    assert.ok(m.content_scripts[0].js.includes('capture.js'));
    assert.equal(m.commands.fill.suggested_key.default, 'Ctrl+Shift+L');
    assert.equal(m.background.type, 'module');
    if (b === 'firefox') assert.deepEqual(m.background.scripts, ['background.js']);
    else assert.equal(m.background.service_worker, 'background.js');
    readFileSync(new URL(`dist/${b}/capture.js`, ext));
  });
}

console.log(`\n${passed} passed`);
