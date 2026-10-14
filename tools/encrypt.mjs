// Gera data.enc.json a partir de um JSON em texto puro (mesmo formato do site).
// Uso: VIP_PW="senha" node tools/encrypt.mjs dados.json > data.enc.json
import { readFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const ITERATIONS = 250000;
const pw = process.env.VIP_PW;
if (!pw || !process.argv[2]) { console.error('Uso: VIP_PW="senha" node tools/encrypt.mjs dados.json'); process.exit(1); }

const obj = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const te = new TextEncoder();
const b64 = (b) => Buffer.from(b).toString('base64');
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj)));
process.stdout.write(JSON.stringify({ v: 1, iter: ITERATIONS, salt: b64(salt), iv: b64(iv), data: b64(ct) }, null, 2) + '\n');
