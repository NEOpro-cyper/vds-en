/**
 * VPS multi-worker proxy pool — OPTIMIZED for high-throughput segment serving.
 *
 *   npm i undici          <-- REQUIRED now (connection pooling + HTTP/2)
 *   node vps-proxy-server.js
 *
 *   PORT=8080 HOST=0.0.0.0 WORKERS=10 node vps-proxy-server.js
 *
 * ---------------------------------------------------------------------------
 * OPTIMIZATIONS vs. original
 * ---------------------------------------------------------------------------
 *   1. CLUSTER MODE      spawns N workers (default = os.cpus().length).
 *                        Your 10-core VPS now uses ALL 10 cores, not just 1.
 *                        Workers auto-restart on crash.
 *
 *   2. CONNECTION POOL   undici Agent with aggressive keep-alive + HTTP/2.
 *                        Reuses TCP+TLS connections to the same upstream,
 *                        eliminating the handshake cost that was dominating
 *                        per-segment latency.
 *
 *   3. HTTP/2            MultiPLEXED streams on a single connection to
 *                        HTTP/2-capable upstreams — many segments in flight
 *                        over ONE connection.
 *
 *   4. DNS CACHE         Custom lookup function caches A/AAAA records for
 *                        60s, removing per-request DNS latency.
 *
 *   5. TOKEN CACHE        LRU cache (10k entries) for encryptToken(). Same
 *                        URL always produces the same token, so encrypting
 *                        the same child URL 1000x in a playlist now costs
 *                        nothing after the first call.
 *
 *   6. SERVER TUNING      keepAliveTimeout 120s, headersTimeout 125s,
 *                        maxConnections 16k — keeps client sockets warm and
 *                        accepts far more concurrent players.
 *
 *   7. PRE-COMPUTED CORS  CORS_HEADERS frozen once, reused via spread.
 *
 *   8. STREAM BACKPRESSURE Upstream pipe uses explicit .pipe(res) with
 *                        error handlers — no unnecessary buffering.
 *
 *   9. SHARED SECRET       Same shared TOKEN_SECRET — APIs keep working
 *                        unchanged. Tokens produced by this server are
 *                        byte-compatible with the old Cloudflare workers.
 *
 * Env:
 *   PORT             listen port (default 8080)
 *   HOST             bind address (default 0.0.0.0)
 *   TOKEN_SECRET     AES-256-GCM secret (default = shared secret of all APIs)
 *   DEFAULT_PROFILE  profile used for root-level /https://... and /v1... paths
 *   PROXY_URL        optional outbound proxy (uses undici ProxyAgent)
 *   WORKERS          cluster worker count (default = os.cpus().length)
 *   NO_CLUSTER=1     force single-process mode (debugging)
 *   UPSTREAM_CONNS   max connections per upstream origin (default 256)
 *   CACHE_DNS_TTL    DNS cache TTL in ms (default 60000)
 */

const http = require("node:http");
const cluster = require("node:cluster");
const os = require("node:os");
const dns = require("node:dns");
const { Readable } = require("node:stream");
const { webcrypto } = require("node:crypto");

// undici is now required (connection pooling is the #1 perf win).
// `npm i undici`. Node 18+ ships undici internally but does NOT expose it
// via require(), so the npm package must be installed.
let undici;
try {
  undici = require("undici");
} catch (e) {
  console.error(
    "[vps-proxy-pool] undici is now REQUIRED for connection pooling.\n" +
      "Run: npm i undici\n" +
      "Then restart the server.",
  );
  process.exit(1);
}
const { Agent, ProxyAgent, setGlobalDispatcher } = undici;
// Use undici's own fetch so we can pass the dispatcher explicitly. Falls back
// to global fetch (which uses the same global dispatcher set below) anyway.
const fetchImpl = undici.fetch || global.fetch;

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || "0.0.0.0";
const TOKEN_SECRET =
  process.env.TOKEN_SECRET ||
  "bbef4e4840ab0a33b6c129f0de8b1a6735471c82f43e9babc4adc64c5959a64a";
const DEFAULT_PROFILE = (process.env.DEFAULT_PROFILE || "movy").toLowerCase();
const WORKERS = Math.max(1, Number(process.env.WORKERS) || os.cpus().length);
const USE_CLUSTER = process.env.NO_CLUSTER !== "1" && WORKERS > 1;
const UPSTREAM_CONNS = Number(process.env.UPSTREAM_CONNS) || 256;
const DNS_TTL = Number(process.env.CACHE_DNS_TTL) || 60_000;

/* ------------------------------------------------------------------ */
/* Worker profiles — unchanged from original.                          */
/* ------------------------------------------------------------------ */

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const PROFILES = {
  va:   { label: "vidfast streams",                       site: "https://vidfast.vc/",   origin: "https://vidfast.vc"   },
  nass: { label: "xpass streams",                          site: "https://play.xpass.top/", origin: "https://play.xpass.top" },
  nest: { label: "vidnest streams",                        site: "https://vidnest.fun/",  origin: "https://vidnest.fun"  },
  ck:   { label: "vidrock streams",                        site: "https://vidrock.to/",   origin: "https://vidrock.to"   },
  pi:   { label: "moviesapi.to streams",                    site: "https://moviesapi.to/",  origin: "https://moviesapi.to"  },
  vy:   { label: "cinejoy streams (movy.sx)",              site: "https://movy.sx/",       origin: "https://movy.sx"       },
  cdn1: { label: "cinejoy streams (cinejoy.pk)",           site: "https://cinejoy.pk/",    origin: "https://cinejoy.pk"    },
  hls:  { label: "generic — no site headers (public CDNs)", site: null,                    origin: null                    },
};

/* ------------------------------------------------------------------ */
/* LRU cache — tiny Map-based, used for encryptToken + playlist URLs   */
/* ------------------------------------------------------------------ */

class LRU {
  constructor(max = 10_000) {
    this.max = max;
    this.map = new Map();
  }
  get(key) {
    if (!this.map.has(key)) return undefined;
    const v = this.map.get(key);
    // move to end (most-recently-used)
    this.map.delete(key);
    this.map.set(key, v);
    return v;
  }
  set(key, value) {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, value);
    if (this.map.size > this.max) {
      const oldest = this.map.keys().next().value;
      this.map.delete(oldest);
    }
  }
}

const tokenCache = new LRU(10_000);

/* ------------------------------------------------------------------ */
/* AES-256-GCM token helpers — same wire format, cached results        */
/* Token: v1.<b64url(iv)>.<b64url(ciphertext+authtag)>                  */
/* Deterministic IV = SHA-256("iv:" + url)[0..12] — same URL = same token */
/* ------------------------------------------------------------------ */

const TOKEN_RE = /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

let _tokenKey = null;
async function getTokenKey() {
  if (!_tokenKey) {
    const digest = await webcrypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(TOKEN_SECRET),
    );
    _tokenKey = await webcrypto.subtle.importKey(
      "raw",
      digest,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
  }
  return _tokenKey;
}

async function decryptToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("bad token format");
  const iv = Buffer.from(parts[1], "base64url");
  const data = Buffer.from(parts[2], "base64url");
  if (iv.length !== 12 || data.length < 17) throw new Error("bad token size");
  const key = await getTokenKey();
  const plain = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(plain);
}

async function encryptToken(rawUrl) {
  const cached = tokenCache.get(rawUrl);
  if (cached) return cached;
  const key = await getTokenKey();
  const digest = await webcrypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode("iv:" + rawUrl),
  );
  const iv = digest.slice(0, 12);
  const ct = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(rawUrl),
  );
  const token = `v1.${Buffer.from(iv).toString("base64url")}.${Buffer.from(ct).toString("base64url")}`;
  tokenCache.set(rawUrl, token);
  return token;
}

async function replaceAsync(str, regex, asyncFn) {
  const matches = [];
  str.replace(regex, (match, ...args) => {
    matches.push(asyncFn(match, ...args));
    return match;
  });
  const values = await Promise.all(matches);
  let i = 0;
  return str.replace(regex, () => values[i++]);
}

/* ------------------------------------------------------------------ */
/* Playlist rewriters — unchanged behavior, just hit the token cache   */
/* ------------------------------------------------------------------ */

async function rewritePlaylistEncrypted(text, selfBase, baseUrl) {
  const lines = text.split("\n");
  const out = new Array(lines.length);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) {
      out[i] = await replaceAsync(line, /URI="([^"]+)"/g, async (m, uri) => {
        if (/^https?:\/\//i.test(uri)) {
          if (uri.startsWith(selfBase)) return m;
          return `URI="${selfBase}/${await encryptToken(uri)}"`;
        }
        const abs = new URL(uri, baseUrl).toString();
        return `URI="${selfBase}/${await encryptToken(abs)}"`;
      });
    } else if (trimmed && /^https?:\/\//i.test(trimmed)) {
      out[i] = trimmed.startsWith(selfBase)
        ? line
        : `${selfBase}/${await encryptToken(trimmed)}`;
    } else if (trimmed) {
      const abs = new URL(trimmed, baseUrl).toString();
      out[i] = `${selfBase}/${await encryptToken(abs)}`;
    } else {
      out[i] = line;
    }
  }
  return replaceAsync(out.join("\n"), /(https?:\/\/[^\s<>"']+)/g, async (m) => {
    if (m.startsWith(selfBase)) return m;
    return `${selfBase}/${await encryptToken(m)}`;
  });
}

function rewritePlaylistPlain(text, selfBase, baseUrl) {
  text = text.replace(/(https?:\/\/[^\s<>"']+)/g, (match) => {
    if (match.startsWith(selfBase)) return match;
    return `${selfBase}/${match}`;
  });
  return text
    .split("\n")
    .map((line) => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith("#") && !trimmed.startsWith("http")) {
        const absoluteUrl = new URL(trimmed, baseUrl).toString();
        return `${selfBase}/${absoluteUrl}`;
      }
      return line;
    })
    .join("\n");
}

/* ------------------------------------------------------------------ */
/* DNS caching — cuts ~10-50ms per request on cold upstreams           */
/* ------------------------------------------------------------------ */

const dnsCache = new Map();
function makeCachedLookup() {
  return (hostname, options, callback) => {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    const key = hostname + ":" + (options.family || 0);
    const cached = dnsCache.get(key);
    if (cached && Date.now() - cached.ts < DNS_TTL) {
      // clone to avoid caller mutating the cached value
      const v = Array.isArray(cached.value) ? cached.value.slice() : cached.value;
      return callback(null, v);
    }
    dns.lookup(hostname, options, (err, value) => {
      if (err) return callback(err);
      dnsCache.set(key, { value, ts: Date.now() });
      callback(null, value);
    });
  };
}

/* ------------------------------------------------------------------ */
/* Upstream dispatcher — connection pooling + HTTP/2 + (optional) proxy */
/* ------------------------------------------------------------------ */

function buildDispatcher() {
  if (process.env.PROXY_URL) {
    console.log(`[vps-proxy-pool] upstream via proxy ${process.env.PROXY_URL}`);
    return new ProxyAgent({
      uri: process.env.PROXY_URL,
      // keep proxy connections warm too
      keepAliveTimeout: 60_000,
      keepAliveMaxTimeout: 600_000,
      connections: UPSTREAM_CONNS,
      bodyTimeout: 0,
      headersTimeout: 30_000,
      connect: { timeout: 10_000, lookup: makeCachedLookup() },
      allowH2: true,
    });
  }
  return new Agent({
    // ----- aggressive keep-alive: this is the single biggest perf win -----
    keepAliveTimeout: 60_000,        // idle socket idle for 60s before close
    keepAliveMaxTimeout: 600_000,    // hard cap 10 min
    keepAliveH1Timeout: 30_000,
    pipelining: 1,                    // HTTP/1.1 pipelining off (safer with CDNs)
    connections: UPSTREAM_CONNS,      // sockets per origin (default 128 -> 256)
    maxCachedMessages: 100,
    bodyTimeout: 0,                   // large segments can take a while
    headersTimeout: 30_000,           // 30s for upstream to send headers
    allowH2: true,                     // HTTP/2 multiplexing where supported
    connect: {
      timeout: 10_000,
      keepAlive: true,
      keepAliveInitialDelay: 30_000,
      lookup: makeCachedLookup(),
    },
  });
}

const dispatcher = buildDispatcher();
setGlobalDispatcher(dispatcher);

/* ------------------------------------------------------------------ */
/* Core proxy handler                                                   */
/* ------------------------------------------------------------------ */

const CORS_HEADERS = Object.freeze({
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "*",
});

function plain(res, status, msg) {
  res.writeHead(status, { "Content-Type": "text/plain", ...CORS_HEADERS });
  res.end(msg);
}

// Pre-built per-profile browser headers — built once at startup.
const PROFILE_BROWSER_HEADERS = {};
for (const [name, p] of Object.entries(PROFILES)) {
  const h = {
    "User-Agent": BROWSER_UA,
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
  };
  if (p.site) {
    h.Referer = p.site;
    h.Origin = p.origin;
  }
  PROFILE_BROWSER_HEADERS[name] = h;
}

async function proxyRequest(req, res, targetUrl, profile, encrypt, selfBase, profileName) {
  const upHeaders = { ...PROFILE_BROWSER_HEADERS[profileName] };
  if (req.headers.range) upHeaders.Range = req.headers.range;

  const ac = new AbortController();
  res.on("close", () => ac.abort());

  let body;
  if (req.method !== "GET" && req.method !== "HEAD") {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    body = Buffer.concat(chunks);
    if (body.length) upHeaders["Content-Length"] = String(body.length);
  }

  let response;
  try {
    response = await fetchImpl(targetUrl, {
      method: req.method,
      headers: upHeaders,
      body: req.method !== "GET" && req.method !== "HEAD" ? body : undefined,
      redirect: "follow",
      signal: ac.signal,
      dispatcher,
    });
  } catch (error) {
    if (ac.signal.aborted) return;
    return plain(res, 502, "Error: " + error.message);
  }

  const contentType = response.headers.get("Content-Type") || "";

  // ---- HLS playlist: rewrite, then return as text ----
  if (contentType.includes("mpegurl") || targetUrl.pathname.endsWith(".m3u8")) {
    let text = await response.text();
    text = encrypt
      ? await rewritePlaylistEncrypted(text, selfBase, targetUrl)
      : rewritePlaylistPlain(text, selfBase, targetUrl);

    const bodyBuf = Buffer.from(text, "utf8");
    res.writeHead(response.status, {
      ...CORS_HEADERS,
      "Content-Type": "application/vnd.apple.mpegurl",
      "Cache-Control": "no-store",
      "Content-Length": String(bodyBuf.length),
      "X-Proxy-Mode": encrypt ? "encrypted" : "plain",
    });
    return res.end(bodyBuf);
  }

  // ---- everything else: STREAM through with minimal header work ----
  const outHeaders = { "X-Proxy-Mode": encrypt ? "encrypted" : "plain" };
  response.headers.forEach((v, k) => {
    const lk = k.toLowerCase();
    if (
      lk === "content-encoding" ||
      lk === "content-length" ||
      lk === "transfer-encoding" ||
      lk === "connection" ||
      lk === "keep-alive" ||
      lk.startsWith("access-control-")
    ) return;
    outHeaders[k] = v;
  });

  res.writeHead(response.status, { ...outHeaders, ...CORS_HEADERS });

  if (!response.body || req.method === "HEAD") return res.end();
  const stream = Readable.fromWeb(response.body);
  stream.on("error", () => {
    try { res.destroy(); } catch (e) {}
  });
  stream.pipe(res);
}

/* ------------------------------------------------------------------ */
/* HTTP server + routing                                                */
/* ------------------------------------------------------------------ */

function createServer() {
  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    req.on("error", () => {});
    res.on("error", () => {});
    try {
      if (req.method === "OPTIONS") {
        res.writeHead(204, CORS_HEADERS);
        return res.end();
      }

      const fwdHost = req.headers["x-forwarded-host"];
      const host = (typeof fwdHost === "string" && fwdHost ? fwdHost : req.headers.host) || "localhost";
      const fwdProto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
      const selfOrigin = `${fwdProto}://${host}`;

      let path = req.url;
      if (path === "/" || path === "/health") {
        const profiles = Object.fromEntries(
          Object.entries(PROFILES).map(([k, v]) => [k, v.label]),
        );
        const body = JSON.stringify(
          { ok: true, profiles, defaultProfile: DEFAULT_PROFILE },
          null,
          2,
        );
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          ...CORS_HEADERS,
        });
        return res.end(body);
      }

      let rest = path.replace(/^\//, "");
      let profileName = DEFAULT_PROFILE;
      const m = rest.match(/^([A-Za-z0-9_-]+)\/([\s\S]*)$/);
      if (m && Object.prototype.hasOwnProperty.call(PROFILES, m[1].toLowerCase())) {
        profileName = m[1].toLowerCase();
        rest = m[2];
      } else if (
        m &&
        (/^https?:\/\//i.test(m[2]) || TOKEN_RE.test(m[2])) &&
        !/^https?:\/\//i.test(rest) &&
        !TOKEN_RE.test(rest)
      ) {
        return plain(
          res,
          404,
          `Unknown profile "${m[1]}". Available: ${Object.keys(PROFILES).join(", ")}`,
        );
      }
      const profile = PROFILES[profileName];
      const selfBase = `${selfOrigin}/${profileName}`;

      // ---- ENCRYPTED MODE ----
      if (TOKEN_RE.test(rest)) {
        let target;
        try {
          target = new URL(await decryptToken(rest));
        } catch (e) {
          return plain(res, 403, "Invalid or tampered token.");
        }
        await proxyRequest(req, res, target, profile, true, selfBase, profileName);
        log(req, res, profileName, "encrypted", started);
        return;
      }

      // ---- PLAIN MODE ----
      if (!/^https?:\/\//i.test(rest)) {
        return plain(
          res,
          400,
          "Invalid proxy usage. Format: https://vps.example.com/{profile}/https://target.com/path",
        );
      }

      let targetUrl;
      try {
        targetUrl = new URL(rest);
      } catch (e) {
        return plain(res, 400, "Invalid target URL provided in path.");
      }

      await proxyRequest(req, res, targetUrl, profile, false, selfBase, profileName);
      log(req, res, profileName, "plain", started);
    } catch (err) {
      if (!res.headersSent) {
        plain(res, 500, "Error: " + (err && err.message ? err.message : String(err)));
      } else {
        try { res.destroy(); } catch (e) {}
      }
    }
  });

  // ----- server tuning: keep client sockets warm, allow many concurrent -----
  server.keepAliveTimeout = 120_000;     // 2 min idle keep-alive
  server.headersTimeout = 125_000;       // MUST be > keepAliveTimeout
  server.requestTimeout = 30_000;        // 30s to receive request headers
  server.timeout = 0;                    // no inactivity timeout (streaming)
  server.maxConnections = 16_384;         // allow many simultaneous players
  server.maxHeaderSize = 16 * 1024;

  server.on("clientError", (err, socket) => {
    try {
      if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    } catch (e) {}
  });
  return server;
}

function log(req, res, profile, mode, started) {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${profile}/${mode} -> ${res.statusCode} (${Date.now() - started}ms)`,
  );
}

/* ------------------------------------------------------------------ */
/* Cluster bootstrap                                                    */
/* ------------------------------------------------------------------ */

function startWorker() {
  // Never crash the process on async errors — log and continue.
  // A crash = Coolify restart = 503 = "CORS error" for the player.
  process.on("unhandledRejection", (reason) =>
    console.error(`[vps-proxy-pool:${process.pid}] unhandledRejection:`, reason),
  );
  process.on("uncaughtException", (err) =>
    console.error(`[vps-proxy-pool:${process.pid}] uncaughtException:`, err),
  );

  const server = createServer();
  server.listen(PORT, HOST, () => {
    console.log(`[vps-proxy-pool:${process.pid}] listening on http://${HOST}:${PORT} (default: ${DEFAULT_PROFILE})`);
  });

  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 3000).unref();
    });
  }
}

if (USE_CLUSTER && cluster.isPrimary) {
  console.log(`[vps-proxy-pool] primary ${process.pid} spawning ${WORKERS} workers`);
  for (let i = 0; i < WORKERS; i++) cluster.fork();
  cluster.on("exit", (worker, code, signal) => {
    console.log(
      `[vps-proxy-pool] worker ${worker.process.pid} died (code=${code} sig=${signal}); respawning`,
    );
    cluster.fork();
  });
  // worker stdout already flows through to primary's stdout in Node
} else {
  startWorker();
}

module.exports = { createServer, PROFILES, encryptToken, decryptToken, TOKEN_RE, buildDispatcher };
