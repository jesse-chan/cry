#!/usr/bin/env node
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const ALGORITHM = 'aes-256-gcm';
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;

// 金鑰來源：環境變數 CRY_KEY，未設定時使用預設密語
const PASSPHRASE = process.env.CRY_KEY ?? 'cry-default-passphrase';

function deriveKey(salt: Buffer): Buffer {
  return scryptSync(PASSPHRASE, salt, 32);
}

function encrypt(plain: string): string {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGORITHM, deriveKey(salt), iv);
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, data]).toString('base64url');
}

function decrypt(encoded: string): string {
  const buf = Buffer.from(encoded, 'base64url');
  if (buf.length < SALT_LEN + IV_LEN + TAG_LEN) {
    throw new Error('密文格式不正確');
  }
  const salt = buf.subarray(0, SALT_LEN);
  const iv = buf.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const tag = buf.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const data = buf.subarray(SALT_LEN + IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALGORITHM, deriveKey(salt), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

function copyToClipboard(text: string): boolean {
  const candidates: [string, string[]][] =
    process.platform === 'darwin'
      ? [['pbcopy', []]]
      : process.platform === 'win32'
        ? [['clip', []]]
        : [
          ['wl-copy', []],
          ['xclip', ['-selection', 'clipboard']],
          ['xsel', ['--clipboard', '--input']],
        ];
  for (const [cmd, args] of candidates) {
    const result = spawnSync(cmd, args, { input: text });
    if (!result.error && result.status === 0) return true;
  }
  return false;
}

function usage(): never {
  console.error('用法: cry -e <字串>   加密');
  console.error('      cry -d <字串>   解密');
  console.error('可用環境變數 CRY_KEY 指定密語');
  process.exit(1);
}

const [mode, input] = process.argv.slice(2);
if (input === undefined || (mode !== '-e' && mode !== '-d')) usage();

let output: string;
try {
  output = mode === '-e' ? encrypt(input) : decrypt(input);
} catch {
  console.error(mode === '-e' ? '加密失敗' : '解密失敗：密文錯誤或密語不符');
  process.exit(1);
}

console.log(output);
if (!copyToClipboard(output)) {
  console.error('(無法複製到剪貼簿)');
}
