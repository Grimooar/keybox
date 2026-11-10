// Тесты проверки паролей: node tests/health.test.mjs
import assert from 'node:assert/strict';
const H = await import('../js/health.js');

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ok  ', name); }
  catch (e) { console.log('  FAIL', name, '\n      ', e.stack); process.exitCode = 1; }
}
const now = Date.now(), DAY = 86400000;
const it = (id, password, extra = {}) => ({ id, type: 'login', name: id, password, createdAt: now, updatedAt: now, ...extra });

await test('слабые, повторы, старые', async () => {
  const items = [
    it('a', '123456'), it('b', 'k7#Qz!vR9$wL2mXp'), it('c', 'k7#Qz!vR9$wL2mXp'),
    it('d', 'Zx8&nB4!tYq1@eUo', { updatedAt: now - 200 * DAY }),
    it('e', '', {}), { id: 'n', type: 'note', password: '123456' },
  ];
  const r = await H.analyze(items, now);
  assert.equal(r.total, 4);
  assert.deepEqual(r.weak.map(x => x.item.id), ['a']);
  assert.equal(r.reused.length, 1);
  assert.deepEqual(r.reused[0].map(x => x.id), ['b', 'c']);
  assert.deepEqual(r.old.map(x => x.id), ['d']);
});

{
  const body = '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0000000000000000000000000000000000A:0\r\n';
  await test('breachCount: k-anonymity', async () => {
    H.clearBreachCache();
    const calls = [];
    const f = async (url, opts) => { calls.push({ url, opts }); return { ok: true, text: async () => body }; };
    assert.equal(await H.breachCount('password', f), 3861493);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://api.pwnedpasswords.com/range/5BAA6');
    assert.equal(calls[0].url.split('/range/')[1].length, 5);
    assert.equal(calls[0].opts.headers['Add-Padding'], 'true');
    assert.ok(!calls[0].url.includes('1E4C9'));
    assert.equal(await H.breachCount('password', f), 3861493);
    assert.equal(calls.length, 1, 'кэш');
  });
  await test('breachCount: не найден, ошибки', async () => {
    H.clearBreachCache();
    assert.equal(await H.breachCount('zz-unique-pass', async () => ({ ok: true, text: async () => body })), 0);
    assert.equal(await H.breachCount('other-pass', async () => { throw new Error('net'); }), null);
    assert.equal(await H.breachCount('third-pass', async () => ({ ok: false })), null);
  });
  await test('checkBreaches: параллелизм и прогресс', async () => {
    H.clearBreachCache();
    let cur = 0, max = 0, prog = 0;
    const f = async () => { cur++; max = Math.max(max, cur); await new Promise(r => setTimeout(r, 5)); cur--; return { ok: true, text: async () => body }; };
    const r = await H.checkBreaches([it('a', 'p1'), it('b', 'p2'), it('c', 'p3'), it('d', 'p4')], { fetchFn: f, onProgress: () => prog++ });
    assert.equal(r.size, 4); assert.equal(prog, 4); assert.ok(max <= 2);
  });
}
console.log(`\n${passed} passed`);
