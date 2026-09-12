import { createNode } from './bsp.js';

// Cloudflare Workers entry. No build step, no secrets, no bindings.
// The node generates its own Ed25519 identity at first boot and publishes
// it through its own /.well-known/jwks.json.
let node = null;

export default {
  async fetch(req, env) {
    if (!node) {
      node = await createNode({
        allowHttpKid: env.BSP_ALLOW_HTTP_KID === '1', // dev/test only; default off
      });
    }
    return node.handle(req);
  },
};
