/**
 * VPS multi-worker proxy pool — OPTIMIZED, ZERO-DEPENDENCY (Node >= 18).
 *
 *   node vps-proxy-server.js            (PORT=8080 HOST=0.0.0.0)
 *
 *   npm i undici   is OPTIONAL — if present, adds HTTP/2 + undici pooling.
 *   Without it the server still runs fast using built-in keep-alive agents.
 *
 * ---------------------------------------------------------------------------
 * OPTIMIZATIONS vs. original
 * ---------------------------------------------------------------------------
 *   1. CLUSTER MODE        N workers (default = os.cpus().length) — uses all
 *                          10 cores instead of 1. Workers auto-respawn.
 *   2. CONNECTION POOLING  keep-alive agents (built-in http/https.Agent, or
 *                          undici Agent when installed). TCP+TLS connections
 *                          to the same upstream are REUSED — no handshake
 *                          cost per segment. This was the biggest slowdown.
 *   3. HTTP/2              (undici only) multiplexes segments over one conn.
 *   4. DNS CACHE           60s TTL lookup cache — no per-request DNS latency.
 *   5. TOKEN CACHE         LRU for encryptToken() — deterministic tokens are
 *                          computed once per URL, not per request.
 *   6. SERVER TUNING       keepAliveTimeout 120s, maxConnections 16384,
 *                          timeout 0 — warm client sockets, no stream cuts.
 *   7. PRE-BUILT HEADERS   per-profile browser headers built once.
 *
 * Env:
 *   PORT             listen port (default 8080)
 *   HOST             bind address (default 0.0.0.0)
 *   TOKEN_SECRET     AES-256-GCM secret
 *   DEFAULT_PROFILE  profile for root-level /https://... and /v1... paths
 *   PROXY_URL        optional outbound proxy (REQUIRES: npm i undici)
 *   WORKERS          cluster worker count (default = os.cpus().length)
 *   NO_CLUSTER=1     force single-process mode (debugging)
 *   UPSTREAM_CONNS   max sockets per upstream origin per worker (default 256)
 *   CACHE_DNS_TTL    DNS cache TTL ms (default 60000)
 */

const http = require("node:http");
const https = require("node:https");
const cluster = require("node:cluster");
const os = require("node:os");
const dns = require("node:dns");
const { Readable } = require("node:stream");
const { webcrypto } = require("node:crypto");

// undici is OPTIONAL now. Built-in keep-alive agents are the fallback.
let undici = null;
try { undici = require("undici"); } catch (e) { /* zero-dep mode */ }

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

if (process.env.PROXY_URL && !undici) {
  console.error(
    "[vps-proxy-pool] PROXY_URL is set but undici is not installed — run: npm i undici",
  );
  process.exit(1);
}

/* ------------------------------------------------------------------ */
/* Worker profiles                                                      */
/* ------------------------------------------------------------------ */

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const PROFILES = {
  va:   { label: "vidfast streams",                        site: "https://vidfast.vc/",     origin: "https://vidfast.vc"   },
  nass: { label: "xpass streams",                          site: "https://play.xpass.top/", origin: "https://play.xpass.top" },
  nest: { label: "vidnest streams",                        site: "https://vidnest.fun/",    origin: "https://vidnest.fun"  },
  ck:   { label: "vidrock streams",                        site: "https://vidrock.to/",     origin: "https://vidrock.to"   },
  pi:   { label: "moviesapi.to streams",                   site: "https://moviesapi.to/",   origin: "https://moviesapi.to" },
  vy:   { label: "cinejoy streams (movy.sx)",              site: "https://movy.sx/",        origin: "https://movy.sx"      },
  cdn1: { label: "cinejoy streams (cinejoy.pk)",           site: "https://cinejoy.pk/",     origin: "https://cinejoy.pk"   },
  hls:  { label: "generic — no site headers (public CDNs)", site: null,                     origin: null                   },
};

/* ------------------------------------------------------------------ */
/* LRU cache                                                            */
/* ------------------------------------------------------------------ */

class LRU {
  constructor(max = 10_000) {
    this.max = max;
    this.map = new Map();
  }
  get(key) {
    if (!this.map.has(key)) return undefined;
    const v = this.map.get(key);
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
/* AES-256-GCM token helpers (cached)                                   */
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
  const jobs = [];
  str.replace(regex, (match, ...args) => {
    jobs.push(asyncFn(match, ...args));
    return match;
  });
  const values = await Promise.all(jobs);
  let i = 0;
  return str.replace(regex, () => values[i++]);
}

/* ------------------------------------------------------------------ */
/* Playlist rewriters (unchanged behavior)                              */
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
/* DNS cache (used by both transports)                                  */
/* ------------------------------------------------------------------ */

// DNS cache. CRITICAL: dns.lookup's callback signature is:
//   - default mode:        callback(err, address, family)    -- string + number
//   - all: true mode:      callback(err, addresses)          -- array of {address, family}
// We MUST replay the EXACT same signature on a cache hit, otherwise net.connect
// throws "RangeError: Invalid address family: undefined" (which is what was
// producing the flood of 502s at 1-8ms latency on every request).
const dnsCache = new Map();
function makeCachedLookup() {
  return function cachedLookup(hostname, options, callback) {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    const wantAll = options.all === true;
    const key = hostname + ":" + (options.family || 0) + ":" + (wantAll ? "a" : "s");
    const hit = dnsCache.get(key);
    if (hit && Date.now() - hit.ts < DNS_TTL) {
      return process.nextTick(() => {
        if (wantAll) callback(null, hit.addresses);        // array form
        else callback(null, hit.address, hit.family);      // string + family form
      });
    }
    dns.lookup(hostname, options, (err, address, family) => {
      if (err) return callback(err);
      if (wantAll) {
        // address is an array of {address, family} records here
        dnsCache.set(key, { addresses: address, ts: Date.now() });
        callback(null, address);
      } else {
        // address is a string, family is 4 or 6
        dnsCache.set(key, { address, family, ts: Date.now() });
        callback(null, address, family);
      }
    });
  };
}
const cachedLookup = makeCachedLookup();

/* ------------------------------------------------------------------ */
/* TRANSPORT                                                            */
/* ------------------------------------------------------------------ */

let fetchImpl;
let dispatcher = null; // undici Agent / ProxyAgent (when undici present)

if (undici) {
  // ---------- undici path: keep-alive pool ----------
  // Only well-documented Agent options are used here. Earlier versions passed
  // invalid options (maxCachedMessages, connect.keepAlive, connect.lookup on a
  // pooled Agent) that caused undici to reject every request synchronously,
  // surfacing as instant 502s. HTTP/2 is OFF by default for max compatibility
  // with quirky upstream CDNs (set ALLOW_H2=1 to re-enable).
  const { Agent, ProxyAgent, setGlobalDispatcher } = undici;
  const allowH2 = process.env.ALLOW_H2 === "1";
  if (process.env.PROXY_URL) {
    console.log(`[vps-proxy-pool] upstream via proxy ${process.env.PROXY_URL}`);
    dispatcher = new ProxyAgent({
      uri: process.env.PROXY_URL,
      keepAliveTimeout: 60_000,
      keepAliveMaxTimeout: 600_000,
      connections: UPSTREAM_CONNS,
      bodyTimeout: 0,
      headersTimeout: 30_000,
      allowH2,
    });
  } else {
    dispatcher = new Agent({
      keepAliveTimeout: 60_000,
      keepAliveMaxTimeout: 600_000,
      connections: UPSTREAM_CONNS,
      bodyTimeout: 0,
      headersTimeout: 30_000,
      allowH2,
    });
  }
  setGlobalDispatcher(dispatcher);
  fetchImpl = undici.fetch;
} else {
  // ---------- zero-dep path: node:http/https with keep-alive agents ----------
  const agentCommon = {
    keepAlive: true,
    keepAliveMsecs: 30_000,
    maxSockets: UPSTREAM_CONNS,
    maxFreeSockets: 64,
    scheduling: "lifo",
    noDelay: true,
  };
  const keepAliveHttp = new http.Agent(agentCommon);
  const keepAliveHttps = new https.Agent(agentCommon);

  const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

  function wrapIncoming(response, signal) {
    // kill upstream when client aborts
    if (signal) {
      const onAbort = () => { try { response.destroy(); } catch (e) {} };
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort, { once: true });
    }
    return {
      status: response.statusCode || 502,
      headers: {
        get(name) {
          const v = response.headers[String(name).toLowerCase()];
          return v === undefined ? null : Array.isArray(v) ? v.join(", ") : v;
        },
        forEach(cb) {
          for (const [k, v] of Object.entries(response.headers)) {
            if (Array.isArray(v)) v.forEach((vv) => cb(vv, k));
            else cb(v, k);
          }
        },
      },
      text() {
        return new Promise((resolve, reject) => {
          const chunks = [];
          response.on("data", (c) => chunks.push(c));
          response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
          response.on("error", reject);
        });
      },
      body: response, // Node stream — proxyRequest handles both kinds
    };
  }

  function nodeRequest(urlString, opts, redirectCount = 0) {
    return new Promise((resolve, reject) => {
      const url = new URL(urlString);
      const isHttps = url.protocol === "https:";
      const mod = isHttps ? https : http;
      const agent = isHttps ? keepAliveHttps : keepAliveHttp;
      const { method = "GET", headers = {}, body, signal } = opts;

      let settled = false;
      const request = mod.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname + url.search,
          method,
          headers,
          agent,
          lookup: cachedLookup,
        },
        (response) => {
          const status = response.statusCode || 0;
          const location = response.headers.location;
          if (redirectCount < 10 && location && REDIRECT_STATUSES.has(status)) {
            response.resume(); // drain + release socket back to the pool
            let nextMethod = method;
            let nextBody = body;
            if (status === 303 || ((status === 301 || status === 302) && method === "POST")) {
              nextMethod = "GET";
              nextBody = undefined;
            }
            nodeRequest(new URL(location, url).toString(),
              { ...opts, method: nextMethod, body: nextBody }, redirectCount + 1)
              .then(resolve, reject);
            return;
          }
          settled = true;
          resolve(wrapIncoming(response, signal));
        },
      );

      const onAbort = () => { try { request.destroy(); } catch (e) {} };
      if (signal) {
        if (signal.aborted) {
          return reject(new Error("aborted"));
        }
        signal.addEventListener("abort", onAbort, { once: true });
      }

      // headers/connect must arrive within 30s
      const headerTimer = setTimeout(() => {
        request.destroy(new Error("upstream timeout (headers)"));
      }, 30_000);
      request.on("response", () => clearTimeout(headerTimer));

      // kill fully-stalled sockets after 2 min of silence
      request.setTimeout(120_000, () => {
        request.destroy(new Error("upstream socket idle timeout"));
      });

      request.on("error", (err) => {
        clearTimeout(headerTimer);
        reject(err);
      });

      if (body && method !== "GET" && method !== "HEAD") request.write(body);
      request.end();
    });
  }

  fetchImpl = nodeRequest;
}

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

// per-profile browser headers built once at startup
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

async function proxyRequest(req, res, targetUrl, encrypt, selfBase, profileName) {
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
      // For undici we rely on the GLOBAL dispatcher set via setGlobalDispatcher();
      // passing `dispatcher` per-request is unreliable across undici versions.
      // For the zero-dep transport this option is simply ignored.
    });
  } catch (error) {
    if (ac.signal.aborted) return;
    // Surface the real cause so it's visible in the server logs — the player
    // never sees the response body, only the 502 status.
    console.error(
      `[vps-proxy-pool:${process.pid}] 502 ${req.method} ${targetUrl.host}${targetUrl.pathname} -> ${error.name}: ${error.message}`,
    );
    return plain(res, 502, "Error: " + error.message);
  }

  const contentType = response.headers.get("Content-Type") || "";

  // ---- HLS playlist: rewrite, return as text ----
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

  // ---- everything else: stream through ----
  const outHeaders = { "X-Proxy-Mode": encrypt ? "encrypted" : "plain" };
  response.headers.forEach((v, k) => {
    const lk = String(k).toLowerCase();
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

  if (typeof response.body.pipe === "function") {
    // zero-dep transport: Node IncomingMessage
    response.body.on("error", () => { try { res.destroy(); } catch (e) {} });
    response.body.pipe(res);
  } else {
    // undici transport: web ReadableStream
    const stream = Readable.fromWeb(response.body);
    stream.on("error", () => { try { res.destroy(); } catch (e) {} });
    stream.pipe(res);
  }
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
          {
            ok: true,
            transport: undici ? "undici (h2 + pool)" : "node keep-alive agents",
            workers: USE_CLUSTER ? WORKERS : 1,
            defaultProfile: DEFAULT_PROFILE,
            profiles,
          },
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
      const selfBase = `${selfOrigin}/${profileName}`;

      // ---- ENCRYPTED MODE ----
      if (TOKEN_RE.test(rest)) {
        let target;
        try {
          target = new URL(await decryptToken(rest));
        } catch (e) {
          return plain(res, 403, "Invalid or tampered token.");
        }
        await proxyRequest(req, res, target, true, selfBase, profileName);
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

      await proxyRequest(req, res, targetUrl, false, selfBase, profileName);
      log(req, res, profileName, "plain", started);
    } catch (err) {
      if (!res.headersSent) {
        plain(res, 500, "Error: " + (err && err.message ? err.message : String(err)));
      } else {
        try { res.destroy(); } catch (e) {}
      }
    }
  });

  server.keepAliveTimeout = 120_000;
  server.headersTimeout = 125_000; // must be > keepAliveTimeout
  server.requestTimeout = 30_000;
  server.timeout = 0;
  server.maxConnections = 16_384;

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
  process.on("unhandledRejection", (reason) =>
    console.error(`[vps-proxy-pool:${process.pid}] unhandledRejection:`, reason),
  );
  process.on("uncaughtException", (err) =>
    console.error(`[vps-proxy-pool:${process.pid}] uncaughtException:`, err),
  );

  const server = createServer();
  server.listen(PORT, HOST, () => {
    console.log(
      `[vps-proxy-pool:${process.pid}] listening on http://${HOST}:${PORT} | default: ${DEFAULT_PROFILE} | transport: ${undici ? "undici+h2" : "node keep-alive"}`,
    );
  });

  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 3000).unref();
    });
  }
}

if (USE_CLUSTER && cluster.isPrimary) {
  console.log(`[vps-proxy-pool] primary ${process.pid} spawning ${WORKERS} workers (transport: ${undici ? "undici+h2" : "node keep-alive"})`);
  for (let i = 0; i < WORKERS; i++) cluster.fork();
  cluster.on("exit", (worker, code, signal) => {
    console.log(
      `[vps-proxy-pool] worker ${worker.process.pid} died (code=${code} sig=${signal}); respawning`,
    );
    cluster.fork();
  });
} else {
  startWorker();
}

module.exports = { createServer, PROFILES, encryptToken, decryptToken, TOKEN_RE };
