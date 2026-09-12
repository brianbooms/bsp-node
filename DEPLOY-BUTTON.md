# Deploy button snippets (fill OWNER after repo creation)

Repo name: `bsp-node`
Placeholder below: `<OWNER>` — the GitHub username/org that owns the repo.

## Cloudflare Workers deploy button (README / landing page)

Markdown:

[![Deploy to Cloudflare Workers](https://deploy.workers.dev/button)](https://deploy.workers.dev/?url=https://github.com/<OWNER>/bsp-node)

HTML:

<a href="https://deploy.workers.dev/?url=https://github.com/<OWNER>/bsp-node"><img src="https://deploy.workers.dev/button" alt="Deploy to Cloudflare Workers"></a>

## Replit import link

Markdown:

[Open in Replit](https://replit.com/github/<OWNER>/bsp-node)

HTML:

<a href="https://replit.com/github/<OWNER>/bsp-node">Open in Replit</a>

## Spots needing OWNER/name

1. README.md — both deploy links (2 occurrences of `<OWNER>`)
2. DEPLOY-BUTTON.md — this file (reference only, not user-facing)
3. Hub landing page `rewards/protocol/run-node/index.html` — deploy button href + Replit href (2 occurrences)
4. `.replit` — no OWNER needed (Replit derives it from the import URL)
5. `wrangler.toml` — `name = "bsp-node"`; no OWNER needed
