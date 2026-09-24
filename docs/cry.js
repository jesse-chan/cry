// 與 cry.ts 相同格式：base64url(salt[16] | iv[12] | tag[16] | ciphertext)
// 金鑰：scrypt(passphrase, salt, N=16384, r=8, p=1, 32 bytes)，即 Node scryptSync 預設值
// 加密：AES-256-GCM

const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

async function pbkdf2Sha256(password, salt, dkLen) {
  const key = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 1 },
    key,
    dkLen * 8,
  );
  return new Uint8Array(bits);
}

function salsa208(B, x) {
  x.set(B);
  const R = (a, b) => (a << b) | (a >>> (32 - b));
  for (let i = 0; i < 8; i += 2) {
    x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9);
    x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
    x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9);
    x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
    x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
    x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
    x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
    x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
    x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9);
    x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
    x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9);
    x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
    x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
    x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
    x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
    x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
  }
  for (let i = 0; i < 16; i++) B[i] = (B[i] + x[i]) | 0;
}

// B、Y 皆為 32*r 個 word；結果寫回 B
function blockMix(B, Y, r, X, tmp) {
  X.set(B.subarray((2 * r - 1) * 16, 2 * r * 16));
  for (let i = 0; i < 2 * r; i++) {
    for (let k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
    salsa208(X, tmp);
    // 偶數塊放前半、奇數塊放後半
    Y.set(X, ((i >> 1) + (i & 1) * r) * 16);
  }
  B.set(Y);
}

function roMix(B, r, N) {
  const words = 32 * r;
  const V = new Uint32Array(words * N);
  const Y = new Uint32Array(words);
  const X = new Uint32Array(16);
  const tmp = new Uint32Array(16);
  for (let i = 0; i < N; i++) {
    V.set(B, i * words);
    blockMix(B, Y, r, X, tmp);
  }
  for (let i = 0; i < N; i++) {
    const j = B[(2 * r - 1) * 16] & (N - 1);
    for (let k = 0; k < words; k++) B[k] ^= V[j * words + k];
    blockMix(B, Y, r, X, tmp);
  }
}

function toWordsLE(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < out.length; i++) out[i] = view.getUint32(i * 4, true);
  return out;
}

function fromWordsLE(words, bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < words.length; i++) view.setUint32(i * 4, words[i], true);
}

export async function scrypt(password, salt, dkLen, N = SCRYPT_N, r = SCRYPT_R, p = SCRYPT_P) {
  const blockBytes = 128 * r;
  const B = await pbkdf2Sha256(password, salt, p * blockBytes);
  for (let i = 0; i < p; i++) {
    const chunk = B.subarray(i * blockBytes, (i + 1) * blockBytes);
    const words = toWordsLE(chunk);
    roMix(words, r, N);
    fromWordsLE(words, chunk);
  }
  return pbkdf2Sha256(password, B, dkLen);
}

function toBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(str) {
  const s = str.trim().replace(/-/g, '+').replace(/_/g, '/');
  let bin;
  try {
    bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  } catch {
    throw new Error('密文格式不正確');
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function aesKey(passphrase, salt, usage) {
  const raw = await scrypt(enc.encode(passphrase), salt, 32);
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [usage]);
}

export async function encrypt(plain, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await aesKey(passphrase, salt, 'encrypt');
  // Web Crypto 輸出為 ciphertext | tag
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));
  const data = sealed.subarray(0, sealed.length - TAG_LEN);
  const tag = sealed.subarray(sealed.length - TAG_LEN);
  const out = new Uint8Array(SALT_LEN + IV_LEN + TAG_LEN + data.length);
  out.set(salt, 0);
  out.set(iv, SALT_LEN);
  out.set(tag, SALT_LEN + IV_LEN);
  out.set(data, SALT_LEN + IV_LEN + TAG_LEN);
  return toBase64Url(out);
}

export async function decrypt(encoded, passphrase) {
  const buf = fromBase64Url(encoded);
  if (buf.length < SALT_LEN + IV_LEN + TAG_LEN) throw new Error('密文格式不正確');
  const salt = buf.subarray(0, SALT_LEN);
  const iv = buf.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const tag = buf.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const data = buf.subarray(SALT_LEN + IV_LEN + TAG_LEN);
  const sealed = new Uint8Array(data.length + TAG_LEN);
  sealed.set(data, 0);
  sealed.set(tag, data.length);
  const key = await aesKey(passphrase, salt, 'decrypt');
  return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, sealed));
}
