# bsp-node

A one-click-deployable reference node for **BSP Draft 0.1** — the open
protocol for portable dollar-denominated rewards that AI agents can earn in
one shop and spend in another.

**Status: DRAFT.** BSP is a working draft, not a standard. This node is a
reference/test implementation built for the L4 interoperability experiment:
two independent implementations proving they interoperate from the frozen
spec alone. A failed interop run is a useful result — it finds spec bugs.

## Deploy it (about 2 clicks)

**Option A — Cloudflare Workers (free tier works):**

[![Deploy to Cloudflare Workers](https://deploy.workers.dev/button)](https://deploy.workers.dev/?url=https://github.com/brianbooms/bsp-node)

Click the button, authorize with your Cloudflare account, and you have a
live BSP node. No build step, no secrets, no bindings: the node generates
its own Ed25519 identity on first boot and publishes it at
`/.well-known/jwks.json`.

**Option B — Replit:**

[Open in Replit](https://replit.com/github/brianbooms/bsp-node) — the Repl
boots `node local.js` and your node is live in the browser tab.

Either way, what you get is YOUR node: your infrastructure, your keys, your
ledger. Then run the interop session (below) to prove you're in.

> Replace `brianbooms` with the repo owner's GitHub username after the repo is
> created. The button target must be the public repo URL.

## What it implements

All of `/bsp/v1/*` per the frozen endpoint contract:

- `POST /bsp/v1/earn` — issue a signed `bsp.Reward`
- `POST /bsp/v1/discover` — find a holder's rewards for a merchant
- `POST /bsp/v1/quote` — price a basket (JCS basket fingerprint, 300s TTL)
- `POST /bsp/v1/authorize` — hold the quoted amount (holder-signed consent required)
- `POST /bsp/v1/redeem` — capture (exactly-once, 409 on double-spend)
- `POST /bsp/v1/settle` — record obligations (**moves no money**)
- `POST /bsp/v1/reverse` — undo a redemption
- `GET /bsp/v1/rewards/:id`, `/redemptions/:id`, `/settlements/:id`, `/reversals/:id`
- `GET /bsp/v1/balance?holder=`
- `GET /.well-known/bsp.json` — capability document
- `GET /.well-known/jwks.json` — the node's public key

Signature profile: JWS Compact, Ed25519, JCS (RFC 8785) canonicalization,
`kid` = HTTPS JWKS URL, ±5-minute clock skew on consent/`requested_at`,
strict expiry on quotes/authorizations. `Idempotency-Key` required on all
mutating endpoints; replays return the original response byte-identical with
`X-Idempotent-Replayed: true`.

## Run the interop session

1. Deploy your node (above). Note its public base URL, e.g.
   `https://bsp-node.<you>.workers.dev`.
2. Read the frozen package: **SPEC-v0.1.md**, **ENDPOINTS.md**,
   **INTEROP-SESSION.md**, **CHECKLIST.md** (published alongside this repo's
   landing page).
3. Run the both-directions session: your client against the reference node,
   and the reference client against your node — full lifecycle plus the
   `409 already_redeemed` and `422 quote_basket_mismatch` boundary failures.
4. Archive the evidence: both git SHAs, spec version, raw traces, both JWKS
   documents, the filled checklist.

Isolation rules: build from the package alone. Questions about intent get
answered by public spec patches, never private coaching.

## Local dev

```sh
node local.js          # boots on :8787 (same core as the Worker)
node test/selftest.mjs # 27 checks: lifecycle + boundary failures, all green
```

Set `BSP_ALLOW_HTTP_KID=1` only for localhost interop testing (permits
`http://` kid URLs for holder keys). Never in production.

## Honest limits

- In-memory ledger: restarts lose state. This is a reference/test node, not
  production infrastructure.
- `settle` records obligations; it does not move money.
- No webhooks are delivered.
- Double-spend resistance under simultaneous concurrency is not load-tested;
  exactly-once is enforced by ledger single-flight.

## License

MIT — see LICENSE. The protocol spec is a public draft; implementations may
be open or closed, yours stays yours.
