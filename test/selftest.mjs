// bsp-node self-test: boots the node in-process and runs a full BSP
// lifecycle plus boundary failures. All green = shippable.
// Usage: node test/selftest.mjs
import { createNode, jcs, b64uEncode, b64uDecode, basketFingerprint } from '../src/bsp.js';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const HERE = dirname(fileURLToPath(import.meta.url));
const FROZEN_VECTOR = join(HERE, 'fixtures', 'happy-lifecycle.json'); // public L4 fixture

const te = new TextEncoder(), td = new TextDecoder();
let pass = 0, fail = 0;
function ok(name, cond, extra = '') {
  if (cond) { pass++; console.log('  PASS', name); }
  else { fail++; console.log('  FAIL', name, extra); }
}

const node = await createNode({ allowHttpKid: true });
const BASE = 'http://127.0.0.1:18787';

async function call(method, path, body = undefined, headers = {}) {
  const req = new Request(BASE + path, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const res = await node.handle(req);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  const h = {};
  res.headers.forEach((v, k) => { h[k] = v; });
  return { status: res.status, json, text, headers: h };
}
const post = (p, b, h) => call('POST', p, b, h);
let keyN = 0;
const K = () => `t-key-${++keyN}-${Date.now()}`;

// ---- holder keypair + local JWKS server (consent is holder-signed) ----
const holderKp = await crypto.subtle.generateKey({ name: 'Ed25519', namedCurve: 'Ed25519' }, true, ['sign', 'verify']);
const holderJwk = await crypto.subtle.exportKey('jwk', holderKp.publicKey);
let holderJwksUrl = '';
const jwksSrv = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ keys: [{ ...holderJwk, kid: holderJwksUrl, use: 'sig', alg: 'EdDSA' }] }));
});
await new Promise((r) => jwksSrv.listen(0, '127.0.0.1', r));
holderJwksUrl = `http://127.0.0.1:${jwksSrv.address().port}/jwks.json`;

async function holderSign(obj) {
  const { proof, ...rest } = obj;
  const payload = b64uEncode(te.encode(jcs(rest)));
  const header = b64uEncode(te.encode(jcs({ alg: 'EdDSA', kid: holderJwksUrl })));
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, holderKp.privateKey, te.encode(header + '.' + payload));
  return { ...rest, proof: { type: 'JWS', jws: `${header}.${payload}.${b64uEncode(new Uint8Array(sig))}` } };
}

// ---- node's own JWKS, for verifying node signatures ----
const jwksRes = await call('GET', '/.well-known/jwks.json');
ok('jwks.json serves', jwksRes.status === 200 && Array.isArray(jwksRes.json.keys) && jwksRes.json.keys.length === 1);
const nodeJwk = jwksRes.json.keys[0];
const nodeKey = await crypto.subtle.importKey('jwk', { ...nodeJwk, key_ops: ['verify'], ext: true },
  { name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['verify']);
async function nodeSigValid(signed) {
  const parts = signed.proof.jws.split('.');
  const { proof, ...rest } = signed;
  if (td.decode(b64uDecode(parts[1])) !== jcs(rest)) return false;
  return crypto.subtle.verify({ name: 'Ed25519' }, nodeKey, b64uDecode(parts[2]), te.encode(parts[0] + '.' + parts[1]));
}

const HOLDER = 'https://customer.example/acct/42';
const MERCHANT = 'https://merchant.example';
const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');

console.log('\n[1] frozen-vector JCS + fingerprint compatibility');
{
  const vec = JSON.parse(readFileSync(FROZEN_VECTOR, 'utf8'));
  const step0 = vec.steps[0];
  const { proof, ...rest } = step0.object;
  ok('JCS matches frozen signing_input_jcs', jcs(rest) === step0.signing_input_jcs);
  ok('basket fingerprint matches frozen vector', (await basketFingerprint(vec.basket)) === vec.basket_fingerprint);
}

console.log('\n[2] capability doc');
{
  const r = await call('GET', '/.well-known/bsp.json');
  ok('bsp.json 200 + draft status', r.status === 200 && r.json.spec === 'bsp/0.1' && r.json.status === 'draft');
}

console.log('\n[3] full lifecycle');
const basket = {
  items: [{ sku: 'dl-0042', name: 'Deep Focus Vol. 1', unit_price: { value: '29.00', currency: 'USD' }, quantity: 1 }],
  totals: { subtotal: { value: '30.00', currency: 'USD' }, tax: { value: '0.00', currency: 'USD' }, shipping: { value: '0.00', currency: 'USD' }, total: { value: '30.00', currency: 'USD' } },
  merchant: MERCHANT,
  window: { from: now(), to: new Date(Date.now() + 15 * 60000).toISOString().replace(/\.\d+Z$/, 'Z') },
};
let reward, quote, auth, redemption;
{
  const r = await post('/bsp/v1/earn', {
    amount: { value: '8.40', currency: 'USD' }, holder: HOLDER,
    constraints: { merchants: [MERCHANT], min_basket: '25.00' },
  }, { 'Idempotency-Key': K() });
  ok('earn 201 issued', r.status === 201 && r.json.state === 'issued');
  ok('earn signature valid', await nodeSigValid(r.json));
  reward = r.json;

  const d = await post('/bsp/v1/discover', { holder: HOLDER, merchant: MERCHANT });
  ok('discover finds reward', d.status === 200 && d.json.rewards.some((x) => x.id === reward.id));

  const q = await post('/bsp/v1/quote', { reward: reward.id, merchant: MERCHANT, basket }, { 'Idempotency-Key': K() });
  ok('quote 200 applicable 8.40', q.status === 200 && q.json.applicable_amount.value === '8.40');
  ok('quote signature valid', await nodeSigValid(q.json));
  quote = q.json;

  const consent = await holderSign({
    id: 'urn:bsp:consent:test1', type: 'bsp.Consent', spec: 'bsp/0.1',
    holder: HOLDER, reward: reward.id, merchants: [MERCHANT], scope: ['redeem'],
    single_use: false, issued_at: now(),
    expires_at: new Date(Date.now() + 3600000).toISOString().replace(/\.\d+Z$/, 'Z'),
  });

  const a = await post('/bsp/v1/authorize', { quote: quote.id, consent, requested_at: now() }, { 'Idempotency-Key': K() });
  ok('authorize 200', a.status === 200 && a.json.type === 'bsp.Authorization');
  ok('authorize signature valid', await nodeSigValid(a.json));
  auth = a.json;

  const rd = await post('/bsp/v1/redeem', {
    authorization: auth.id, quote: quote.id, order_ref: 'order-test-001', basket, requested_at: now(),
  }, { 'Idempotency-Key': K() });
  ok('redeem 200', rd.status === 200 && rd.json.captured_amount.value === '8.40');
  ok('redeem signature valid', await nodeSigValid(rd.json));
  redemption = rd.json;

  const s = await post('/bsp/v1/settle', {
    redemption: redemption.id,
    allocation: { type: 'bsp.CommissionAllocation', spec: 'bsp/0.1',
      gross: { value: '10.00', currency: 'USD' },
      allocations: [{ party: 'holder_or_creator', share: '0.75' }, { party: 'network', share: '0.25' }] },
  }, { 'Idempotency-Key': K() });
  ok('settle 200 records obligations', s.status === 200 && /obligations only/i.test(s.json.note));
  ok('settle signature valid', await nodeSigValid(s.json));

  const bal = await call('GET', `/bsp/v1/balance?holder=${encodeURIComponent(HOLDER)}`);
  ok('balance excludes redeemed', bal.status === 200 && !bal.json.reward_ids.includes(reward.id));

  const g = await call('GET', `/bsp/v1/rewards/${encodeURIComponent(reward.id)}`);
  ok('reward read shows redeemed (re-signed)', g.status === 200 && g.json.state === 'redeemed' && (await nodeSigValid(g.json)));
}

console.log('\n[4] boundary failures');
{
  // second redeem, different key -> 409
  const r = await post('/bsp/v1/redeem', {
    authorization: auth.id, quote: quote.id, order_ref: 'order-test-002', basket, requested_at: now(),
  }, { 'Idempotency-Key': K() });
  ok('double redeem -> 409 already_redeemed', r.status === 409 && r.json.error === 'already_redeemed');

  // tampered basket -> 422
  const r2 = await post('/bsp/v1/earn', { amount: { value: '5.00', currency: 'USD' }, holder: HOLDER }, { 'Idempotency-Key': K() });
  const q2 = await post('/bsp/v1/quote', { reward: r2.json.id, merchant: MERCHANT, basket }, { 'Idempotency-Key': K() });
  const consent2 = await holderSign({
    id: 'urn:bsp:consent:test2', type: 'bsp.Consent', spec: 'bsp/0.1',
    holder: HOLDER, reward: r2.json.id, merchants: [MERCHANT], scope: ['redeem'],
    single_use: false, issued_at: now(),
    expires_at: new Date(Date.now() + 3600000).toISOString().replace(/\.\d+Z$/, 'Z'),
  });
  const a2 = await post('/bsp/v1/authorize', { quote: q2.json.id, consent: consent2, requested_at: now() }, { 'Idempotency-Key': K() });
  const badBasket = JSON.parse(JSON.stringify(basket));
  badBasket.totals.total.value = '31.00';
  const rd2 = await post('/bsp/v1/redeem', {
    authorization: a2.json.id, quote: q2.json.id, order_ref: 'order-test-003', basket: badBasket, requested_at: now(),
  }, { 'Idempotency-Key': K() });
  ok('tampered basket -> 422 quote_basket_mismatch', rd2.status === 422 && rd2.json.error === 'quote_basket_mismatch');

  // invalid signature on consent -> 401/403 family (fresh reward+quote so
  // the consent check is what fires, not already_authorized)
  const r3 = await post('/bsp/v1/earn', { amount: { value: '5.00', currency: 'USD' }, holder: HOLDER }, { 'Idempotency-Key': K() });
  const q3 = await post('/bsp/v1/quote', { reward: r3.json.id, merchant: MERCHANT, basket }, { 'Idempotency-Key': K() });
  const badConsent = JSON.parse(JSON.stringify(consent2));
  badConsent.reward = r3.json.id;
  badConsent.proof.jws = badConsent.proof.jws.slice(0, -4) + 'AAAA';
  const a3 = await post('/bsp/v1/authorize', { quote: q3.json.id, consent: badConsent, requested_at: now() }, { 'Idempotency-Key': K() });
  ok('forged consent rejected', a3.status === 401 || a3.status === 403, JSON.stringify(a3.json));

  // bad allocation sum -> 422
  const s2 = await post('/bsp/v1/settle', {
    redemption: redemption.id,
    allocation: { allocations: [{ party: 'a', share: '0.75' }, { party: 'b', share: '0.20' }] },
  }, { 'Idempotency-Key': K() });
  ok('allocation != 1.00 -> 422 allocation_invalid', s2.status === 422 && s2.json.error === 'allocation_invalid');

  // missing idempotency key -> 400
  const m = await post('/bsp/v1/earn', { amount: { value: '1.00', currency: 'USD' }, holder: HOLDER });
  ok('missing Idempotency-Key -> 400', m.status === 400 && m.json.error === 'missing_idempotency_key');

  // idempotent replay -> byte-identical + header
  const key = K();
  const e1 = await post('/bsp/v1/earn', { amount: { value: '2.00', currency: 'USD' }, holder: HOLDER }, { 'Idempotency-Key': key });
  const e2 = await post('/bsp/v1/earn', { amount: { value: '9.99', currency: 'USD' }, holder: 'someone-else' }, { 'Idempotency-Key': key });
  ok('idempotent replay byte-identical + header', e2.headers['x-idempotent-replayed'] === 'true' && e2.text === e1.text);

  // reversal: full reversal restores reward to issued
  const rv = await post('/bsp/v1/reverse', { redemption: redemption.id, reason: 'refund' }, { 'Idempotency-Key': K() });
  ok('reverse 200', rv.status === 200 && rv.json.type === 'bsp.Reversal');
  const g2 = await call('GET', `/bsp/v1/rewards/${encodeURIComponent(reward.id)}`);
  ok('full reversal restores issued (re-signed)', g2.status === 200 && g2.json.state === 'issued' && (await nodeSigValid(g2.json)));
  const rv2 = await post('/bsp/v1/reverse', { redemption: redemption.id, reason: 'refund' }, { 'Idempotency-Key': K() });
  ok('second reversal -> 409 already_reversed', rv2.status === 409 && rv2.json.error === 'already_reversed');

  // unknown reward -> 404
  const uq = await post('/bsp/v1/quote', { reward: 'urn:bsp:reward:nope', merchant: MERCHANT, basket }, { 'Idempotency-Key': K() });
  ok('unknown reward -> 404', uq.status === 404 && uq.json.error === 'unknown_reward');
}

jwksSrv.close();

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
