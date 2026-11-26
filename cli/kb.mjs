#!/usr/bin/env node
// kb - Ключница для программ (участник-сервис, например Директор). Справка: node cli/kb.mjs help
// Ключи - из переменных окружения (см. cli/lib.mjs), запуск через хранилище ключей: vault.py run kb_* -- kb ...
import { execFileSync, spawn } from 'node:child_process';
import { main, winCommand } from './lib.mjs';

const win = process.platform === 'win32';

const code = await main(process.argv.slice(2), {
  env: process.env,
  fetch: (...a) => globalThis.fetch(...a),
  out: line => process.stdout.write(line + '\n'),
  err: line => process.stderr.write(line + '\n'),
  // Дочерний процесс видит тот же терминал; значение - только в его окружении. Без shell: на Windows
  // .cmd/.bat идут через cmd.exe с проверенными аргументами (winCommand)
  spawn: (cmd, args, env) => new Promise(resolve => {
    const c = win ? winCommand(cmd, args, { env }) : { file: cmd, args };
    const child = spawn(c.file, c.args, { stdio: 'inherit', env, shell: false, windowsVerbatimArguments: !!c.verbatim });
    child.on('error', e => { process.stderr.write('kb: не удалось запустить ' + cmd + ' (' + e.code + ')\n'); resolve(127); });
    child.on('exit', (c, sig) => resolve(c ?? (sig ? 128 : 1)));
  }),
  // Windows: файл с ключами - только текущему пользователю (наследование прав снято)
  protectFile: path => {
    const user = process.env.USERDOMAIN ? process.env.USERDOMAIN + '\\' + process.env.USERNAME : process.env.USERNAME;
    if (!user) return false;
    execFileSync('icacls', [path, '/inheritance:r', '/grant:r', user + ':F'], { stdio: 'ignore' });
    return true;
  },
});
process.exitCode = code;
