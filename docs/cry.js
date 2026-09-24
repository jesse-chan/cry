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

// SHA-256 / HMAC / PBKDF2 以純 JS 實作：
// Firefox 的 Web Crypto PBKDF2 輸出上限為 2048 bits，scrypt 需要 1024 bytes 會丟出 OperationError
// https://bugzilla.mozilla.org/show_bug.cgi?id=1469482
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256(data) {
  const bitLen = data.length * 8;
  const padded = new Uint8Array(((data.length + 9 + 63) >> 6) << 6);
  padded.set(data);
  padded[data.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  view.setUint32(padded.length - 4, bitLen >>> 0);

  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + W[i];
      const t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) outView.setUint32(i * 4, H[i]);
  return out;
}

function hmacSha256(key, msg) {
  const k = new Uint8Array(64);
  k.set(key.length > 64 ? sha256(key) : key);
  const inner = new Uint8Array(64 + msg.length);
  const outer = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    inner[i] = k[i] ^ 0x36;
    outer[i] = k[i] ^ 0x5c;
  }
  inner.set(msg, 64);
  outer.set(sha256(inner), 64);
  return sha256(outer);
}

function pbkdf2Sha256(password, salt, dkLen, iterations = 1) {
  const out = new Uint8Array(dkLen);
  const block = new Uint8Array(salt.length + 4);
  block.set(salt);
  for (let i = 1, pos = 0; pos < dkLen; i++, pos += 32) {
    new DataView(block.buffer).setUint32(salt.length, i);
    let u = hmacSha256(password, block);
    const t = u.slice();
    for (let n = 1; n < iterations; n++) {
      u = hmacSha256(password, u);
      for (let j = 0; j < 32; j++) t[j] ^= u[j];
    }
    out.set(t.subarray(0, Math.min(32, dkLen - pos)), pos);
  }
  return out;
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
