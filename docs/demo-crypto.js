// doublethink browser demo crypto. This reimplements, in the browser, the exact
// client-side derivation from internal/clientcrypto (Go) so the demo can create a
// channel and seal/open messages the same way the real clients do. It is verified
// byte-for-byte against a Go test vector (see docs/demo-crypto.parity.js).
//
// Primitives, matching the Go side exactly:
//   - HKDF over BLAKE2b-256 (Go uses hkdf.New(blake2b.New256, ...)).
//   - secretbox = XSalsa20-Poly1305 (NaCl), via vendored tweetnacl.
//   - base32 (RFC 4648, no padding, the GenerateSecret/RegistrationKey encoding).
//   - derivation labels identical to Go: "doublethink-auth-v1",
//     "doublethink-enc-v1", "enc a->b" / "enc b->a", "doublethink-challenge-v1".
//
// NO secret is embedded here. The demo generates a fresh secret in the browser per
// run. This file is plain ES modules, no build step, no third-party CDN.

// ---- BLAKE2b (256-bit), compact public-domain implementation ----
// Adapted from the reference BLAKE2b in JavaScript (CC0). Produces a 32-byte digest.
const B2B_IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372,
  0x5f1d36f1, 0xa54ff53a, 0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
  0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);
const B2B_SIGMA = new Uint8Array([
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,
  11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4, 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8,
  9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13, 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9,
  12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11, 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10,
  6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5, 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0,
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,
]);
const b2b_v = new Uint32Array(32);
const b2b_m = new Uint32Array(32);
function ADD64AA(v, a, b) {
  const o0 = v[a] + v[b];
  let o1 = v[a + 1] + v[b + 1];
  if (o0 >= 0x100000000) o1++;
  v[a] = o0; v[a + 1] = o1;
}
function ADD64AC(v, a, b0, b1) {
  let o0 = v[a] + b0;
  if (b0 < 0) o0 += 0x100000000;
  let o1 = v[a + 1] + b1;
  if (o0 >= 0x100000000) o1++;
  v[a] = o0; v[a + 1] = o1;
}
function B2B_GET32(arr, i) { return arr[i] ^ (arr[i + 1] << 8) ^ (arr[i + 2] << 16) ^ (arr[i + 3] << 24); }
function B2B_G(a, b, c, d, ix, iy) {
  const x0 = b2b_m[ix], x1 = b2b_m[ix + 1], y0 = b2b_m[iy], y1 = b2b_m[iy + 1];
  ADD64AA(b2b_v, a, b); ADD64AC(b2b_v, a, x0, x1);
  let xor0 = b2b_v[d] ^ b2b_v[a], xor1 = b2b_v[d + 1] ^ b2b_v[a + 1];
  b2b_v[d] = xor1; b2b_v[d + 1] = xor0;
  ADD64AA(b2b_v, c, d);
  xor0 = b2b_v[b] ^ b2b_v[c]; xor1 = b2b_v[b + 1] ^ b2b_v[c + 1];
  b2b_v[b] = (xor0 >>> 24) ^ (xor1 << 8); b2b_v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);
  ADD64AA(b2b_v, a, b); ADD64AC(b2b_v, a, y0, y1);
  xor0 = b2b_v[d] ^ b2b_v[a]; xor1 = b2b_v[d + 1] ^ b2b_v[a + 1];
  b2b_v[d] = (xor0 >>> 16) ^ (xor1 << 16); b2b_v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);
  ADD64AA(b2b_v, c, d);
  xor0 = b2b_v[b] ^ b2b_v[c]; xor1 = b2b_v[b + 1] ^ b2b_v[c + 1];
  b2b_v[b] = (xor1 >>> 31) ^ (xor0 << 1); b2b_v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
}
function b2bCompress(ctx, last) {
  for (let i = 0; i < 16; i++) { b2b_v[i] = ctx.h[i]; b2b_v[i + 16] = B2B_IV[i]; }
  b2b_v[24] ^= ctx.t; b2b_v[25] ^= ctx.t / 0x100000000;
  if (last) { b2b_v[28] = ~b2b_v[28]; b2b_v[29] = ~b2b_v[29]; }
  for (let i = 0; i < 32; i++) b2b_m[i] = B2B_GET32(ctx.b, 4 * i);
  for (let i = 0; i < 12; i++) {
    B2B_G(0, 8, 16, 24, B2B_SIGMA[i*16+0]*2, B2B_SIGMA[i*16+1]*2);
    B2B_G(2, 10, 18, 26, B2B_SIGMA[i*16+2]*2, B2B_SIGMA[i*16+3]*2);
    B2B_G(4, 12, 20, 28, B2B_SIGMA[i*16+4]*2, B2B_SIGMA[i*16+5]*2);
    B2B_G(6, 14, 22, 30, B2B_SIGMA[i*16+6]*2, B2B_SIGMA[i*16+7]*2);
    B2B_G(0, 10, 20, 30, B2B_SIGMA[i*16+8]*2, B2B_SIGMA[i*16+9]*2);
    B2B_G(2, 12, 22, 24, B2B_SIGMA[i*16+10]*2, B2B_SIGMA[i*16+11]*2);
    B2B_G(4, 14, 16, 26, B2B_SIGMA[i*16+12]*2, B2B_SIGMA[i*16+13]*2);
    B2B_G(6, 8, 18, 28, B2B_SIGMA[i*16+14]*2, B2B_SIGMA[i*16+15]*2);
  }
  for (let i = 0; i < 16; i++) ctx.h[i] = ctx.h[i] ^ b2b_v[i] ^ b2b_v[i + 16];
}
function b2bInit(outlen) {
  const ctx = { b: new Uint8Array(128), h: new Uint32Array(16), t: 0, c: 0, outlen };
  for (let i = 0; i < 16; i++) ctx.h[i] = B2B_IV[i];
  ctx.h[0] ^= 0x01010000 ^ outlen;
  return ctx;
}
function b2bUpdate(ctx, input) {
  for (let i = 0; i < input.length; i++) {
    if (ctx.c === 128) { ctx.t += ctx.c; b2bCompress(ctx, false); ctx.c = 0; }
    ctx.b[ctx.c++] = input[i];
  }
}
function b2bFinal(ctx) {
  ctx.t += ctx.c;
  while (ctx.c < 128) ctx.b[ctx.c++] = 0;
  b2bCompress(ctx, true);
  const out = new Uint8Array(ctx.outlen);
  for (let i = 0; i < ctx.outlen; i++) out[i] = ctx.h[i >> 2] >> (8 * (i & 3));
  return out;
}
function blake2b256(input, key) {
  const ctx = b2bInit(32);
  if (key && key.length) { b2bUpdate(ctx, key); ctx.c = 128; }
  b2bUpdate(ctx, input);
  return b2bFinal(ctx);
}

// ---- HMAC-BLAKE2b and HKDF (RFC 5869), matching Go hkdf.New(blake2b.New256,...) ----
const HASH_LEN = 32, BLOCK = 128; // BLAKE2b block size is 128
function hmacBlake2b(key, msg) {
  if (key.length > BLOCK) key = blake2b256(key);
  const k = new Uint8Array(BLOCK); k.set(key);
  const ipad = new Uint8Array(BLOCK), opad = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
  const inner = blake2b256(concat(ipad, msg));
  return blake2b256(concat(opad, inner));
}
function hkdf(ikm, salt, info, length) {
  // extract
  if (!salt || salt.length === 0) salt = new Uint8Array(HASH_LEN);
  const prk = hmacBlake2b(salt, ikm);
  // expand
  const out = new Uint8Array(length);
  let t = new Uint8Array(0), pos = 0, counter = 1;
  while (pos < length) {
    t = hmacBlake2b(prk, concat(t, info, new Uint8Array([counter])));
    const take = Math.min(t.length, length - pos);
    out.set(t.subarray(0, take), pos); pos += take; counter++;
  }
  return out;
}

// ---- helpers ----
function concat(...arrs) {
  let n = 0; for (const a of arrs) n += a.length;
  const out = new Uint8Array(n); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
const enc = new TextEncoder();
function label(s) { return enc.encode(s); }
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32encode(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) { value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32decode(str) {
  str = str.toUpperCase().replace(/=+$/, "");
  let bits = 0, value = 0; const out = [];
  for (const c of str) { const idx = B32.indexOf(c); if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; } }
  return new Uint8Array(out);
}
function b64encode(bytes) { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); }
function b64decode(str) { const s = atob(str); const out = new Uint8Array(s.length); for (let i=0;i<s.length;i++) out[i]=s.charCodeAt(i); return out; }
function toHex(b) { return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join(""); }

// ---- doublethink derivation, matching internal/clientcrypto ----
const AUTH_TAG = "doublethink-auth-v1";
const ENC_TAG = "doublethink-enc-v1";
const CHALLENGE_TAG = "doublethink-challenge-v1";

function derive(ikm, info) { return hkdf(ikm, null, label(info), 32); }

export function generateSecret() {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  return base32encode(raw).toUpperCase();
}
export function authKey(secret) { return derive(base32decode(secret), AUTH_TAG); }
export function registrationKey(secret) { return base32encode(authKey(secret)); }
export function challengeResponse(secret, challenge) {
  return hkdf(authKey(secret), challenge, label(CHALLENGE_TAG), 32);
}
// session keys: per-direction. RoleA sends a->b, recv b->a; RoleB mirrored.
export function session(secret, role) {
  const kenc = derive(base32decode(secret), ENC_TAG);
  const aToB = derive(kenc, "enc a->b");
  const bToA = derive(kenc, "enc b->a");
  return role === "a" ? { send: aToB, recv: bToA } : { send: bToA, recv: aToB };
}

// ---- secretbox via vendored tweetnacl (loaded separately as nacl) ----
// seal returns nonce||ciphertext (matching Go Seal output layout).
export function seal(sess, plaintext, naclLib) {
  const nonce = new Uint8Array(24); crypto.getRandomValues(nonce);
  const ct = naclLib.secretbox(plaintext, nonce, sess.send);
  return concat(nonce, ct);
}
export function open(sess, blob, naclLib) {
  const nonce = blob.subarray(0, 24);
  const ct = blob.subarray(24);
  const pt = naclLib.secretbox.open(ct, nonce, sess.recv);
  return pt; // null on failure
}

export const _internal = { blake2b256, hkdf, base32encode, base32decode, b64encode, b64decode, toHex, concat, label };
