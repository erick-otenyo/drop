// Browser side of the drop join protocol. Bundled into web/vendor.js.
//
// Pure-JS crypto is used on purpose: LAN mode is served over plain HTTP, where
// the browser's WebCrypto (crypto.subtle) is unavailable.
import { RistrettoPoint, ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

const enc = new TextEncoder();
const dec = new TextDecoder();

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function b64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBigLE(b) {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
}

// The generator both sides derive from the session id and the join code.
function generator(sid, code) {
  return RistrettoPoint.hashToCurve(
    sha512(concat(enc.encode('drop-cpace-v1\0'), enc.encode(sid), enc.encode('\0'), enc.encode(code)))
  );
}

// Step 1: returns { X, finish }. Send X to the host, then call finish(Y).
export function joinStart(sid, code, rand = randomBytes(64)) {
  const G = generator(sid, code);
  let x = bytesToBigLE(rand) % ed25519.CURVE.n;
  if (x === 0n) x = 1n;
  const X = G.multiply(x).toRawBytes();
  return {
    X,
    finish(Y) {
      const Yp = RistrettoPoint.fromHex(Y);
      if (Yp.equals(RistrettoPoint.ZERO)) throw new Error('bad host share');
      const K = Yp.multiply(x).toRawBytes();
      return deriveKeys(sid, X, Y, K);
    },
  };
}

export function deriveKeys(sid, X, Y, K) {
  const salt = sha512(concat(enc.encode(sid), X, Y));
  const okm = hkdf(sha256, K, salt, enc.encode('drop-v1 keys'), 128);
  const confirmKey = okm.slice(64, 96);
  return {
    c2s: okm.slice(0, 32),
    s2c: okm.slice(32, 64),
    token: b64(okm.slice(96, 128)),
    clientMac: hmac(sha256, confirmKey, enc.encode('client')),
    hostMac: hmac(sha256, confirmKey, enc.encode('server')),
  };
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// seal/open move JSON values. aad names the direction ("c2s" or "s2c").
export function seal(key, aad, value) {
  const n = randomBytes(24);
  const c = xchacha20poly1305(key, n, enc.encode(aad)).encrypt(enc.encode(JSON.stringify(value)));
  return { n: b64(n), c: b64(c) };
}

export function open(key, aad, box) {
  const pt = xchacha20poly1305(key, unb64(box.n), enc.encode(aad)).decrypt(unb64(box.c));
  return JSON.parse(dec.decode(pt));
}
