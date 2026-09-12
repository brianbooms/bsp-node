// Local runner: `node local.js` — same core as the Worker, for one-click
// Replit deploys and local interop testing.
import { createNode } from './src/bsp.js';
import http from 'node:http';

const PORT = Number(process.env.PORT || 8787);
const node = await createNode({ allowHttpKid: true });

const server = http.createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks);
    const url = `http://127.0.0.1:${PORT}${req.url}`;
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (Array.isArray(v)) v.forEach((x) => headers.append(k, x));
      else if (v !== undefined) headers.set(k, v);
    }
    const request = new Request(url, {
      method: req.method,
      headers,
      body: raw.length && req.method !== 'GET' && req.method !== 'HEAD' ? raw : undefined,
    });
    const out = await node.handle(request);
    const outBody = Buffer.from(await out.arrayBuffer());
    const outHeaders = {};
    out.headers.forEach((v, k) => { outHeaders[k] = v; });
    res.writeHead(out.status, outHeaders);
    res.end(outBody);
  } catch (e) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'internal', message: String(e && e.message || e) }));
  }
});

server.listen(PORT, () => {
  console.log(`bsp-node listening on http://127.0.0.1:${PORT}`);
  console.log(`capability doc: http://127.0.0.1:${PORT}/.well-known/bsp.json`);
});
