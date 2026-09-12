/*
 * bsp-node — BSP Draft 0.1 reference node core.
 *
 * Platform-agnostic: runs on Cloudflare Workers (src/index.js) and on plain
 * Node 18+ (local.js). Uses only WebCrypto + fetch. No dependencies.
 *
 * STATUS: DRAFT. BSP is a working draft, not a standard. This node is a
 * reference/test implementation for the L4 interoperability experiment.
 * Settlement records obligations; it does not move money.
 */

// ---------------------------------------------------------------------------
// JCS — RFC 8785 JSON Canonicalization Scheme (strict subset we need)
// ---------------------------------------------------------------------------
function jcsString(s) {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (cp < 0x20) out += '\\u' + cp.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

export function jcs(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'string') return jcsString(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (typeof value === 'object') {
    // sort by UTF-16 code units
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => jcsString(k) + ':' + jcs(value[k])).join(',') + '}';
  }
  throw new Error('unsupported type for JCS');
}

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------
export function b64uEncode(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64uDecode(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
const te = new TextEncoder();
const td = new TextDecoder();

// ---------------------------------------------------------------------------
// decimal-string arithmetic (no floats anywhere)
// ---------------------------------------------------------------------------
function parseDec(v) {
  const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(String(v));
  if (!m) throw new Error('bad decimal: ' + v);
  const frac = m[3] || '';
  return { n: BigInt((m[1] === '-' ? '-' : '') + m[2] + frac), s: frac.length };
}
function align(a, b) {
  const s = Math.max(a.s, b.s);
  return [a.n * 10n ** BigInt(s - a.s), b.n * 10n ** BigInt(s - b.s), s];
}
export function decCmp(a, b) {
  const [x, y] = align(parseDec(a), parseDec(b));
  return x < y ? -1 : x > y ? 1 : 0;
}
export function decEq(a, b) { return decCmp(a, b) === 0; }
export function decMin(a, b) { return decCmp(a, b) <= 0 ? String(a) : String(b); }
export function decSub(a, b) {
  const [x, y, s] = align(parseDec(a), parseDec(b));
  let d = x - y;
  const neg = d < 0n;
  if (neg) d = -d;
  let str = d.toString().padStart(s + 1, '0');
  const out = s === 0 ? str : str.slice(0, -s) + '.' + str.slice(-s);
  return (neg ? '-' : '') + out;
}
export function decAdd(a, b) {
  const [x, y, s] = align(parseDec(a), parseDec(b));
  const sum = x + y;
  const neg = sum < 0n;
  const d = neg ? -sum : sum;
  let str = d.toString().padStart(s + 1, '0');
  const out = s === 0 ? str : str.slice(0, -s) + '.' + str.slice(-s);
  return (neg ? '-' : '') + out;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
export function nowIso() { return new Date().toISOString().replace(/\.\d+Z$/, 'Z'); }
function randId(prefix) {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  return `urn:bsp:${prefix}:` + b64uEncode(bytes).slice(0, 12).toLowerCase();
}
async function sha256hex(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export async function basketFingerprint(basket) {
  return 'sha256:' + (await sha256hex(te.encode(jcs(basket))));
}
function err(code, message, status) {
  const e = new Error(message);
  e.code = code; e.status = status;
  return e;
}
function validAmount(a) {
  return a && typeof a === 'object' && typeof a.value === 'string' &&
    /^\d+(\.\d+)?$/.test(a.value) && a.currency === 'USD';
}
function skewOk(iso, nowMs, windowMs = 5 * 60 * 1000) {
  const t = Date.parse(iso);
  return Number.isFinite(t) && Math.abs(nowMs - t) <= windowMs;
}

// ---------------------------------------------------------------------------
// node
// ---------------------------------------------------------------------------
export async function createNode(opts = {}) {
  const allowHttpKid = !!opts.allowHttpKid;
  const quoteTtlSeconds = 300;

  // Runtime-generated node identity. Keys are born on first boot and
  // published through the node's own JWKS — nothing to provision.
  const keypair = await crypto.subtle.generateKey({ name: 'Ed25519', namedCurve: 'Ed25519' }, true, ['sign', 'verify']);
  const pubJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);

  const rewards = new Map();        // id -> signed Reward (latest state)
  const quotes = new Map();        // id -> signed Quote
  const auths = new Map();         // id -> signed Authorization
  const redemptions = new Map();   // id -> signed Redemption
  const settlements = new Map();   // id -> signed Settlement
  const reversals = new Map();     // id -> signed Reversal
  const consents = new Map();      // id -> signed Consent
  const idem = new Map();          // endpoint:key -> {status, headers, body}
  const orderRefs = new Map();     // order_ref -> redemption id

  function kidFor(reqUrl) {
    return new URL('/.well-known/jwks.json', reqUrl).toString();
  }

  async function sign(obj, reqUrl) {
    const { proof, ...rest } = obj;
    const payload = b64uEncode(te.encode(jcs(rest)));
    const header = b64uEncode(te.encode(jcs({ alg: 'EdDSA', kid: kidFor(reqUrl) })));
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, keypair.privateKey, te.encode(header + '.' + payload));
    return { ...rest, proof: { type: 'JWS', jws: `${header}.${payload}.${b64uEncode(new Uint8Array(sig))}` } };
  }

  async function fetchJwks(kid) {
    let u;
    try { u = new URL(kid); } catch { throw err('invalid_signature', 'kid is not a URL', 401); }
    if (u.protocol !== 'https:' && !(allowHttpKid && (u.protocol === 'http:'))) {
      throw err('invalid_signature', 'kid must be HTTPS', 401);
    }
    const r = await fetch(kid, { headers: { accept: 'application/json' } });
    if (!r.ok) throw err('invalid_signature', 'kid JWKS unreachable', 401);
    return r.json();
  }

  // Verify a signed BSP object (holder-signed Consent or any signed envelope).
  async function verifySigned(signed) {
    const jws = signed && signed.proof && signed.proof.jws;
    if (!jws || typeof jws !== 'string') throw err('invalid_signature', 'missing proof.jws', 401);
    const parts = jws.split('.');
    if (parts.length !== 3) throw err('invalid_signature', 'malformed JWS', 401);
    let header;
    try { header = JSON.parse(td.decode(b64uDecode(parts[0]))); }
    catch { throw err('invalid_signature', 'bad JWS header', 401); }
    if (header.alg !== 'EdDSA') throw err('invalid_signature', 'unsupported alg', 401);
    if (!header.kid) throw err('invalid_signature', 'missing kid', 401);
    const doc = await fetchJwks(header.kid);
    const keys = (doc.keys || []).filter((k) => k.kty === 'OKP' && k.crv === 'Ed25519' && k.x);
    // kid identifies the JWKS document; accept a JWK whose kid matches, else the single key
    let jwk = keys.find((k) => k.kid === header.kid) || (keys.length === 1 ? keys[0] : null);
    if (!jwk) throw err('invalid_signature', 'no usable key in JWKS', 401);
    const key = await crypto.subtle.importKey('jwk', { ...jwk, key_ops: ['verify'], ext: true },
      { name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['verify']);
    const { proof, ...rest } = signed;
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key,
      b64uDecode(parts[2]), te.encode(parts[0] + '.' + parts[1]));
    if (!ok) throw err('invalid_signature', 'signature mismatch', 401);
    // payload must be the JCS of the object minus proof
    const payloadJson = td.decode(b64uDecode(parts[1]));
    if (payloadJson !== jcs(rest)) throw err('invalid_signature', 'payload/object mismatch', 401);
    return header.kid;
  }

  function resolveRef(ref, map, unknownCode) {
    if (!ref) throw err('invalid_request', 'missing reference', 400);
    const id = typeof ref === 'string' ? ref : ref.id;
    const obj = map.get(id);
    if (!obj) throw err(unknownCode, 'not found: ' + id, 404);
    return obj;
  }

  function expired(iso, nowMs) { return Date.parse(iso) <= nowMs; }

  async function verifyConsent(consentRef, { holder, rewardId, merchant }, nowMs) {
    if (!consentRef) throw err('consent_required', 'agent spend requires holder consent', 403);
    const consent = typeof consentRef === 'string'
      ? consents.get(consentRef) || (() => { throw err('consent_invalid', 'unknown consent', 403); })()
      : consentRef;
    if (consent.type !== 'bsp.Consent') throw err('consent_invalid', 'not a bsp.Consent', 403);
    await verifySigned(consent); // throws consent_invalid/invalid_signature family
    if (consent.holder !== holder) throw err('consent_invalid', 'consent holder mismatch', 403);
    if (consent.reward !== rewardId) throw err('consent_invalid', 'consent reward mismatch', 403);
    if (!(consent.merchants || []).includes(merchant)) throw err('scope_denied', 'merchant outside consent scope', 403);
    if (!((consent.scope || []).includes('redeem'))) throw err('scope_denied', 'redeem not in consent scope', 403);
    if (consent.expires_at && expired(consent.expires_at, nowMs)) throw err('consent_expired', 'consent expired', 403);
    if (!skewOk(consent.issued_at, nowMs)) throw err('consent_invalid', 'consent issued_at outside skew window', 403);
    consents.set(consent.id, consent);
    return consent;
  }

  function json(status, body, extraHeaders = {}) {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json; charset=utf-8', ...extraHeaders },
    });
  }
  function problem(e) {
    return json(e.status || 500, { error: e.code || 'internal', message: e.message || 'internal error' });
  }

  // Idempotency wrapper for mutating endpoints
  async function idempotent(endpoint, req, fn) {
    const key = req.headers.get('Idempotency-Key');
    if (!key) throw err('missing_idempotency_key', 'Idempotency-Key header required', 400);
    const slot = endpoint + ':' + key;
    if (idem.has(slot)) {
      const s = idem.get(slot);
      return new Response(s.body, { status: s.status, headers: { ...s.headers, 'X-Idempotent-Replayed': 'true', 'content-type': 'application/json; charset=utf-8' } });
    }
    const res = await fn();
    const body = await res.text();
    const headers = {};
    res.headers.forEach((v, k) => { if (k.toLowerCase() !== 'x-idempotent-replayed') headers[k] = v; });
    idem.set(slot, { status: res.status, headers, body });
    return new Response(body, { status: res.status, headers: { ...headers, 'content-type': 'application/json; charset=utf-8' } });
  }

  async function handle(req) {
    const url = new URL(req.url);
    const path = url.pathname;
    const nowMs = Date.now();
    try {
      // ---- capability + JWKS ----
      if (req.method === 'GET' && path === '/.well-known/bsp.json') {
        return json(200, {
          spec: 'bsp/0.1', status: 'draft',
          operations: ['earn', 'discover', 'balance', 'quote', 'authorize', 'redeem', 'settle', 'reverse'],
          currencies: ['USD'],
          jwks_uri: kidFor(req.url),
          quote_ttl_seconds: quoteTtlSeconds,
          idempotency: 'Idempotency-Key header required on all mutating endpoints',
          notes: [
            'BSP is a working draft, not a standard.',
            'Settlement records obligations; it does not move money.',
          ],
        });
      }
      if (req.method === 'GET' && path === '/.well-known/jwks.json') {
        return json(200, { keys: [{ ...pubJwk, kid: kidFor(req.url), use: 'sig', alg: 'EdDSA' }] });
      }

      const m = path.match(/^\/bsp\/v1\/(earn|discover|quote|authorize|redeem|settle|reverse)$/);
      if (!m) {
        const r = path.match(/^\/bsp\/v1\/(rewards|redemptions|settlements|reversals)\/(.+)$/);
        if (req.method === 'GET' && r) {
          const map = { rewards, redemptions, settlements, reversals }[r[1]];
          const obj = map.get(decodeURIComponent(r[2]));
          if (!obj) return json(404, { error: 'unknown_' + r[1].slice(0, -1), message: 'not found' });
          return json(200, obj);
        }
        if (req.method === 'GET' && path === '/bsp/v1/balance') {
          const holder = url.searchParams.get('holder');
          if (!holder) return json(400, { error: 'invalid_request', message: 'holder query param required' });
          const ids = [], balances = {};
          for (const rw of rewards.values()) {
            if (rw.holder === holder && rw.state === 'issued') {
              ids.push(rw.id);
              balances[rw.amount.currency] = balances[rw.amount.currency]
                ? decAdd(balances[rw.amount.currency], rw.amount.value) : rw.amount.value;
            }
          }
          return json(200, { holder, balances: Object.entries(balances).map(([currency, value]) => ({ currency, value })), reward_ids: ids });
        }
        return json(404, { error: 'invalid_request', message: 'unknown route' });
      }

      const op = m[1];
      const body = req.method === 'POST' ? await req.json().catch(() => null) : null;
      if (req.method !== 'POST' || !body) return json(400, { error: 'invalid_request', message: 'POST with JSON body required' });

      // ---- earn ----
      if (op === 'earn') {
        return await idempotent('earn', req, async () => {
          if (!validAmount(body.amount)) throw err('invalid_request', 'amount {value, currency:USD} required', 400);
          if (typeof body.holder !== 'string' || !body.holder) throw err('invalid_request', 'holder required', 400);
          const reward = {
            id: randId('reward'), type: 'bsp.Reward', spec: 'bsp/0.1',
            amount: { value: String(body.amount.value), currency: 'USD' },
            state: 'issued', issuer: new URL(req.url).origin, holder: body.holder,
            redeemable: true,
            ...(body.constraints ? { constraints: body.constraints } : {}),
            ...(body.attribution ? { attribution: body.attribution } : {}),
            issued_at: nowIso(),
          };
          const signed = await sign(reward, req.url);
          rewards.set(signed.id, signed);
          return json(201, signed);
        });
      }

      // ---- discover ----
      if (op === 'discover') {
        if (typeof body.holder !== 'string' || typeof body.merchant !== 'string')
          return json(400, { error: 'invalid_request', message: 'holder and merchant required' });
        const out = [];
        for (const rw of rewards.values()) {
          if (rw.holder !== body.holder || rw.state !== 'issued') continue;
          const merchants = rw.constraints && rw.constraints.merchants;
          if (!merchants || merchants.includes(body.merchant)) out.push(rw);
        }
        return json(200, { rewards: out });
      }

      // ---- quote ----
      if (op === 'quote') {
        return await idempotent('quote', req, async () => {
          const reward = resolveRef(body.reward, rewards, 'unknown_reward');
          if (reward.state !== 'issued') {
            throw err(reward.state === 'redeemed' ? 'already_redeemed' : 'already_authorized',
              'reward is ' + reward.state, 409);
          }
          if (typeof body.merchant !== 'string' || !body.basket || typeof body.basket !== 'object')
            throw err('invalid_request', 'merchant and basket required', 400);
          const merchants = reward.constraints && reward.constraints.merchants;
          if (merchants && !merchants.includes(body.merchant))
            throw err('scope_denied', 'merchant not in reward constraints', 403);
          const total = body.basket.totals && body.basket.totals.total;
          if (!validAmount(total)) throw err('invalid_request', 'basket.totals.total required', 400);
          const min = reward.constraints && reward.constraints.min_basket;
          if (min && decCmp(total.value, min) < 0)
            throw err('basket_below_minimum', `basket ${total.value} below minimum ${min}`, 422);
          const fp = await basketFingerprint(body.basket);
          const applicable = decMin(reward.amount.value, total.value);
          const quote = {
            id: randId('quote'), type: 'bsp.Quote', spec: 'bsp/0.1',
            reward: reward.id, merchant: body.merchant,
            basket_fingerprint: fp,
            applicable_amount: { value: applicable, currency: 'USD' },
            amount_due_after: { value: decSub(total.value, applicable), currency: 'USD' },
            expires_at: new Date(nowMs + quoteTtlSeconds * 1000).toISOString().replace(/\.\d+Z$/, 'Z'),
          };
          const signed = await sign(quote, req.url);
          quotes.set(signed.id, signed);
          return json(200, signed);
        });
      }

      // ---- authorize ----
      if (op === 'authorize') {
        return await idempotent('authorize', req, async () => {
          if (!body.requested_at || !skewOk(body.requested_at, nowMs))
            throw err('invalid_request', 'requested_at required within ±5 minutes', 400);
          const quote = resolveRef(body.quote, quotes, 'unknown_quote');
          if (expired(quote.expires_at, nowMs)) throw err('quote_expired', 'quote expired', 422);
          const reward = rewards.get(quote.reward);
          if (!reward) throw err('unknown_reward', 'reward for quote not found', 404);
          if (reward.state !== 'issued')
            throw err(reward.state === 'redeemed' ? 'already_redeemed' : 'already_authorized', 'reward is ' + reward.state, 409);
          await verifyConsent(body.consent, { holder: reward.holder, rewardId: reward.id, merchant: quote.merchant }, nowMs);
          reward.state = 'authorized';
          const reSigned = await sign({ ...reward, state: 'authorized' }, req.url);
          rewards.set(reward.id, reSigned);
          const authorization = {
            id: randId('auth'), type: 'bsp.Authorization', spec: 'bsp/0.1',
            quote: quote.id, holder: reward.holder,
            consent: typeof body.consent === 'string' ? body.consent : body.consent.id,
            authorized_at: nowIso(), expires_at: quote.expires_at,
          };
          const signed = await sign(authorization, req.url);
          auths.set(signed.id, signed);
          return json(200, signed);
        });
      }

      // ---- redeem ----
      if (op === 'redeem') {
        return await idempotent('redeem', req, async () => {
          if (!body.requested_at || !skewOk(body.requested_at, nowMs))
            throw err('invalid_request', 'requested_at required within ±5 minutes', 400);
          const authorization = resolveRef(body.authorization, auths, 'unknown_authorization');
          if (expired(authorization.expires_at, nowMs)) throw err('authorization_expired', 'authorization expired', 422);
          const quote = resolveRef(body.quote, quotes, 'unknown_quote');
          if (authorization.quote !== quote.id) throw err('invalid_request', 'authorization/quote mismatch', 400);
          const reward = rewards.get(quote.reward);
          if (!reward) throw err('unknown_reward', 'reward for quote not found', 404);
          if (reward.state === 'redeemed') throw err('already_redeemed', 'reward already redeemed', 409);
          if (reward.state !== 'authorized') throw err('invalid_request', 'reward is not authorized', 400);
          // consent re-validated at capture
          const consentRef = body.consent || authorization.consent;
          await verifyConsent(consentRef, { holder: reward.holder, rewardId: reward.id, merchant: quote.merchant }, nowMs);
          if (expired(quote.expires_at, nowMs)) throw err('quote_expired', 'quote expired', 422);
          if (!body.basket) throw err('invalid_request', 'basket required', 400);
          const fp = await basketFingerprint(body.basket);
          if (fp !== quote.basket_fingerprint) throw err('quote_basket_mismatch', 'basket fingerprint mismatch', 422);
          const captured = body.captured_amount ? String(body.captured_amount.value) : quote.applicable_amount.value;
          if (body.captured_amount && !validAmount(body.captured_amount))
            throw err('invalid_request', 'captured_amount malformed', 400);
          if (decCmp(captured, quote.applicable_amount.value) > 0)
            throw err('amount_exceeds_applicable', 'capture above quoted amount', 422);
          if (!body.order_ref || typeof body.order_ref !== 'string')
            throw err('invalid_request', 'order_ref required', 400);
          const seen = orderRefs.get(body.order_ref);
          if (seen && seen !== authorization.id)
            throw err('duplicate_order_ref', 'order_ref seen with different envelope', 409);
          const remainder = decSub(reward.amount.value, captured);
          let childId = null;
          if (decCmp(remainder, '0') > 0) {
            const child = {
              id: randId('reward'), type: 'bsp.Reward', spec: 'bsp/0.1',
              amount: { value: remainder, currency: 'USD' },
              state: 'issued', issuer: reward.issuer, holder: reward.holder, redeemable: true,
              ...(reward.constraints ? { constraints: reward.constraints } : {}),
              parent: reward.id, issued_at: nowIso(),
            };
            const signedChild = await sign(child, req.url);
            rewards.set(signedChild.id, signedChild);
            childId = signedChild.id;
          }
          const reSigned = await sign({ ...reward, state: 'redeemed' }, req.url);
          rewards.set(reward.id, reSigned);
          const redemption = {
            id: randId('redemption'), type: 'bsp.Redemption', spec: 'bsp/0.1',
            authorization: authorization.id, quote: quote.id,
            order_ref: body.order_ref,
            captured_amount: { value: captured, currency: 'USD' },
            ...(childId ? { remainder_reward: childId } : {}),
            redeemed_at: nowIso(),
          };
          const signed = await sign(redemption, req.url);
          redemptions.set(signed.id, signed);
          orderRefs.set(body.order_ref, authorization.id);
          return json(200, signed);
        });
      }

      // ---- settle ----
      if (op === 'settle') {
        return await idempotent('settle', req, async () => {
          const redemption = resolveRef(body.redemption, redemptions, 'unknown_redemption');
          const allocation = body.allocation;
          if (!allocation || !Array.isArray(allocation.allocations))
            throw err('invalid_request', 'allocation.allocations required', 400);
          let sum = '0';
          for (const a of allocation.allocations) {
            if (typeof a.share !== 'string' || !/^\d+(\.\d+)?$/.test(a.share))
              throw err('allocation_invalid', 'share must be a decimal string', 422);
            sum = decAdd(sum, a.share);
          }
          if (!decEq(sum, '1.00')) throw err('allocation_invalid', 'shares must sum to exactly 1.00', 422);
          const settlement = {
            id: randId('settlement'), type: 'bsp.Settlement', spec: 'bsp/0.1',
            redemption: redemption.id, allocation,
            recorded_at: nowIso(),
            note: 'Records obligations only. Moves no money.',
          };
          const signed = await sign(settlement, req.url);
          settlements.set(signed.id, signed);
          return json(200, signed);
        });
      }

      // ---- reverse ----
      if (op === 'reverse') {
        return await idempotent('reverse', req, async () => {
          const redemption = resolveRef(body.redemption, redemptions, 'unknown_redemption');
          if (!['cancel', 'refund', 'fraud', 'expired'].includes(body.reason))
            throw err('invalid_request', 'reason must be cancel|refund|fraud|expired', 400);
          if (redemption.reversed_at && !redemption.partially_reversed)
            throw err('already_reversed', 'redemption already reversed', 409);
          const amount = body.amount ? String(body.amount.value) : redemption.captured_amount.value;
          if (body.amount && !validAmount(body.amount)) throw err('invalid_request', 'amount malformed', 400);
          if (decCmp(amount, redemption.captured_amount.value) > 0)
            throw err('invalid_request', 'reversal amount exceeds captured', 400);
          const full = decEq(amount, redemption.captured_amount.value) && !redemption.remainder_reward;
          // find the parent reward via the quote chain
          const quote = quotes.get(redemption.quote);
          const parent = quote && rewards.get(quote.reward);
          let restoredId = null;
          if (full && parent) {
            const reSigned = await sign({ ...parent, state: 'issued' }, req.url);
            rewards.set(parent.id, reSigned);
            restoredId = parent.id;
          } else if (parent) {
            const child = {
              id: randId('reward'), type: 'bsp.Reward', spec: 'bsp/0.1',
              amount: { value: amount, currency: 'USD' },
              state: 'issued', issuer: parent.issuer, holder: parent.holder, redeemable: true,
              ...(parent.constraints ? { constraints: parent.constraints } : {}),
              parent: parent.id, issued_at: nowIso(),
            };
            const signedChild = await sign(child, req.url);
            rewards.set(signedChild.id, signedChild);
            restoredId = signedChild.id;
          }
          const updated = await sign({ ...redemption, ...(full ? { reversed_at: nowIso() } : { partially_reversed: true }) }, req.url);
          redemptions.set(redemption.id, updated);
          const reversal = {
            id: randId('reversal'), type: 'bsp.Reversal', spec: 'bsp/0.1',
            redemption: redemption.id, reason: body.reason,
            amount: { value: amount, currency: 'USD' },
            ...(restoredId ? { restored_reward: restoredId } : {}),
            reversed_at: nowIso(),
          };
          const signed = await sign(reversal, req.url);
          reversals.set(signed.id, signed);
          return json(200, signed);
        });
      }

      return json(404, { error: 'invalid_request', message: 'unknown route' });
    } catch (e) {
      return problem(e);
    }
  }

  return { handle, _internals: { jcs, sign, verifySigned, basketFingerprint } };
}
