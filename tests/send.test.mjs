// Тесты клиента одноразовой отправки: node tests/send.test.mjs
import assert from 'node:assert/strict';
const S = await import('../js/send.js');
const C = await import('../js/crypto.js');

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ok  ', name); } catch (e) { console.log('  FAIL', name, '\n      ', e.stack); process.exitCode = 1; }
}

await test('шифрование и расшифровка: round-trip', async () => {
  const text = 'пароль: Tr0ub4dor&3 🔑\nвторая строка';
  const s = await S.sealSend(text);
  assert.match(s.id, /^[0-9a-f]{32}$/);
  assert.ok(!s.body.includes('Tr0ub4dor'));
  assert.equal(await S.openSend(s.id, s.key, s.body), text);
});

await test('неверный ключ не открывает', async () => {
  const s = await S.sealSend('секрет');
  await assert.rejects(S.openSend(s.id, C.b64e(C.randomBytes(32)), s.body));
});

await test('AD привязана к id: шифртекст под другой ссылкой не открывается', async () => {
  const s = await S.sealSend('секрет');
  await assert.rejects(S.openSend(C.randomHex(16), s.key, s.body));
});

await test('ссылка и разбор фрагмента', async () => {
  const s = await S.sealSend('x');
  const link = S.sendLink('https://grimooar.github.io/keybox/index.html#старое', s.id, s.key);
  assert.equal(link, `https://grimooar.github.io/keybox/send.html#${s.id}.${s.key}`);
  assert.deepEqual(S.parseFragment(new URL(link).hash), { id: s.id, key: s.key });
  assert.equal(S.parseFragment('#abc.def'), null);
  assert.equal(S.parseFragment(''), null);
});

await test('fetchSend: 404 -> null, иначе расшифрованный текст', async () => {
  const s = await S.sealSend('hello');
  const ok = await S.fetchSend(s.id, s.key, { apiUrl: 'https://x', fetchFn: async () => new Response(JSON.stringify({ body: s.body, viewsLeft: 0 }), { status: 200 }) });
  assert.deepEqual(ok, { text: 'hello', viewsLeft: 0 });
  assert.equal(await S.fetchSend(s.id, s.key, { apiUrl: 'https://x', fetchFn: async () => new Response('{}', { status: 404 }) }), null);
});

console.log(`\n${passed} тестов прошло${process.exitCode ? ', есть ошибки' : ''}`);
