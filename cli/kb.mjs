#!/usr/bin/env node
// kb - Ключница для программ (участник-сервис, например Директор). Справка: node cli/kb.mjs help
// Ключи - из переменных окружения (см. cli/lib.mjs), запуск через хранилище ключей: vault.py run kb_* -- kb ...
import { spawn } from 'node:child_process';
import { main } from './lib.mjs';

const code = await main(process.argv.slice(2), {
  env: process.env,
  fetch: (...a) => globalThis.fetch(...a),
  out: line => process.stdout.write(line + '\n'),
  err: line => process.stderr.write(line + '\n'),
  // Дочерний процесс видит тот же терминал; значение - только в его окружении
  spawn: (cmd, args, env) => new Promise(resolve => {
    const child = spawn(cmd, args, { stdio: 'inherit', env, shell: false });
    child.on('error', e => { process.stderr.write('kb: не удалось запустить ' + cmd + ' (' + e.code + ')\n'); resolve(127); });
    child.on('exit', (c, sig) => resolve(c ?? (sig ? 128 : 1)));
  }),
});
process.exitCode = code;
