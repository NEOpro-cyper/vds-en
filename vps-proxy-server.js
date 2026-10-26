/**
 * VPS multi-worker proxy pool — replaces multiple Cloudflare proxy workers
 * with ONE Node process. Zero dependencies (Node >= 18).
 *
 *   node vps-proxy-server.js            (PORT=8080 HOST=0.0.0.0)
 *
 * Each "profile" = one former Cloudflare worker (its own upstream headers):
 *
 *   GET /{profile}/https://upstream.com/path      plain mode  (/url proxying)
 *   GET /{profile}/v1.<iv>.<data>                 encrypted mode (AES-256-GCM)
 *   GET /https://upstream.com/path                plain mode, DEFAULT_PROFILE
 *   GET /v1.<iv>.<data>                           encrypted mode, DEFAULT_PROFILE
 *   GET /health                                   profile list + status
 *
 * The APIs point at it like a worker — e.g. for the encrypted mode set:
 *   EN_WORKER_URL=https://vps.example.com:8080/movy        (feb-real-usage)
 *   WORKER_URL_EN=https://vps.example.com:8080/moviesapi   (movies-api etc.)
 *
 * Behavior mirrors the Cloudflare workers: per-profile Referer/Origin + a
 * Chrome/148 browser header set, Range forwarding, m3u8 playlist rewriting
 * (plain: child URLs prefixed; encrypted: child URLs re-tokenized so no
 * upstream URL ever leaks), CORS everywhere, 403 on tampered tokens.
 *
 * Env:
 *   PORT             listen port (default 8080)
 *   HOST             bind address (default 0.0.0.0)
 *   TOKEN_SECRET     AES-256-GCM secret (default = shared secret of all APIs)
 *   DEFAULT_PROFILE  profile used for root-level /https://... and /v1... paths
 *   PROXY_URL        optional outbound proxy (requires: npm i undici)
 */

const http = require("node:http");
const { Readable } = require("node:stream");
const { webcrypto } = require("node:crypto");

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || "0.0.0.0";
const TOKEN_SECRET =
  process.env.TOKEN_SECRET ||
  "bbef4e4840ab0a33b6c129f0de8b1a6735471c82f43e9babc4adc64c5959a64a";
const DEFAULT_PROFILE = (process.env.DEFAULT_PROFILE || "movy").toLowerCase();

/* ------------------------------------------------------------------ */
/* Worker profiles — one per former Cloudflare worker.                 */
/* To add a new worker: copy a block, change site/origin (the Chrome   */
/* browser header set is shared). Route: /<key>/https://...            */
/* ------------------------------------------------------------------ */

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const PROFILES = {
  by: {
    label: "movy.sx streams (replaces the movy Cloudflare worker)",
    site: "https://movy.sx/",
    origin: "https://movy.sx",
  },
  api: {
    label: "moviesapi.to streams (replaces the moviesapi Cloudflare worker)",
    site: "https://moviesapi.to/",
    origin: "https://moviesapi.to",
  },
  none: {
    label: "generic — no site headers (public CDNs)",
    site: null,
    origin: null,
  },
};

/* ---------------- AES-256-GCM token helpers (?data=en) ------------------ */
/* Token: v1.<b64url(iv)>.<b64url(ciphertext+authtag)>                      */
/* Deterministic IV = SHA-256("iv:" + url)[0..12] — same URL = same token.  */

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

/** Decrypt an API token into the raw stream URL. Throws on any tampering. */
async function decryptToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("bad token format");
  const iv = Buffer.from(parts[1], "base64url");
  const data = Buffer.from(parts[2], "base64url");
  if (iv.length !== 12 || data.length < 17) throw new Error("bad token size");
  const key = await getTokenKey();
  // WebCrypto expects ciphertext WITH the 16-byte auth tag appended
  const plain = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(plain);
}

/** Encrypt a raw URL with the deterministic IV (same URL = same token). */
async function encryptToken(rawUrl) {
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
  return `v1.${Buffer.from(iv).toString("base64url")}.${Buffer.from(ct).toString("base64url")}`;
}

async function replaceAsync(str, regex, asyncFn) {
  const jobs = [];
  str.replace(regex, (match, ...args) => {
    jobs.push(asyncFn(match, ...args));
    return match;
  });
  const values = await Promise.all(jobs);
  return str.replace(regex, () => values.shift());
}

/**
 * ENCRYPTED playlist rewrite: every child URL (absolute, relative, or inside
 * URI="..." attributes) is re-encrypted as a token pointing back at this
 * server's profile route, so NO real upstream URL appears in the playlist.
 */
async function rewritePlaylistEncrypted(text, selfBase, baseUrl) {
  const lines = text.split("\n");
  const out = new Array(lines.length);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) {
      // tag line: rewrite URI="..." attributes only (EXTINF etc. untouched)
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
  // safety pass: tokenize any absolute URL that slipped through in an unusual tag
  return replaceAsync(out.join("\n"), /(https?:\/\/[^\s<>"']+)/g, async (m) => {
    if (m.startsWith(selfBase)) return m;
    return `${selfBase}/${await encryptToken(m)}`;
  });
}

/** PLAIN playlist rewrite (same two passes as the Cloudflare workers). */
function rewritePlaylistPlain(text, selfBase, baseUrl) {
  // 1. absolute URLs -> route through the proxy (prevent double-proxying)
  text = text.replace(/(https?:\/\/[^\s<>"']+)/g, (match) => {
    if (match.startsWith(selfBase)) return match;
    return `${selfBase}/${match}`;
  });
  // 2. relative segment lines -> resolve against the playlist URL, then prefix
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
/* Optional outbound proxy (undici ProxyAgent)                          */
/* ------------------------------------------------------------------ */

let dispatcher = null;
if (process.env.PROXY_URL) {
  try {
    const { ProxyAgent } = require("undici");
    dispatcher = new ProxyAgent(process.env.PROXY_URL);
    console.log(`[proxy] upstream requests via ${process.env.PROXY_URL}`);
  } catch (e) {
    console.error("PROXY_URL is set but undici is not installed — run: npm i undici");
    process.exit(1);
  }
}

/* ------------------------------------------------------------------ */
/* Core proxy handler                                                   */
/* ------------------------------------------------------------------ */

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "*",
};

function plain(res, status, msg) {
  res.writeHead(status, { "Content-Type": "text/plain", ...CORS_HEADERS });
  res.end(msg);
}

async function proxyRequest(req, res, targetUrl, profile, encrypt, selfBase) {
  // Upstream headers: Chrome/148 browser set + per-profile site headers
  const upHeaders = {
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
  if (profile.site) {
    upHeaders.Referer = profile.site;
    upHeaders.Origin = profile.origin;
  }
  const range = req.headers.range;
  if (range) upHeaders.Range = range; // seeking / byte-range playlists

  // abort upstream when the player disconnects
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
    response = await fetch(targetUrl, {
      method: req.method,
      headers: upHeaders,
      body: req.method !== "GET" && req.method !== "HEAD" ? body : undefined,
      redirect: "follow",
      signal: ac.signal,
      ...(dispatcher ? { dispatcher } : {}),
    });
  } catch (error) {
    if (ac.signal.aborted) return; // client went away
    return plain(res, 500, "Error: " + error.message);
  }

  const contentType = response.headers.get("Content-Type") || "";

  // ---- HLS playlist: rewrite, then return text ----
  if (contentType.includes("mpegurl") || targetUrl.pathname.endsWith(".m3u8")) {
    let text = await response.text();
    text = encrypt
      ? await rewritePlaylistEncrypted(text, selfBase, targetUrl)
      : rewritePlaylistPlain(text, selfBase, targetUrl);

    const body = Buffer.from(text, "utf8");
    res.writeHead(response.status, {
      ...CORS_HEADERS,
      "Content-Type": "application/vnd.apple.mpegurl",
      "Cache-Control": "no-store", // URLs carry expiring signed tokens
      "Content-Length": String(body.length),
      "X-Proxy-Mode": encrypt ? "encrypted" : "plain",
    });
    return res.end(body);
  }

  // ---- everything else (segments, keys, images): STREAM through ----
  const outHeaders = {};
  response.headers.forEach((v, k) => {
    const lk = k.toLowerCase();
    // hop-by-hop + body-framing headers Node manages itself; content-length
    // is omitted because undici may have decompressed the body (length shift)
    if (["content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"].includes(lk)) return;
    outHeaders[k] = v;
  });
  outHeaders["X-Proxy-Mode"] = encrypt ? "encrypted" : "plain";
  res.writeHead(response.status, { ...outHeaders, ...CORS_HEADERS });

  if (!response.body || req.method === "HEAD") return res.end();
  const stream = Readable.fromWeb(response.body);
  stream.pipe(res);
  stream.on("error", () => res.destroy());
}

/* ------------------------------------------------------------------ */
/* HTTP server + routing                                                */
/* ------------------------------------------------------------------ */

function createServer() {
  return http.createServer(async (req, res) => {
    const started = Date.now();
    try {
      // CORS preflight — same as the workers
      if (req.method === "OPTIONS") {
        res.writeHead(204, CORS_HEADERS);
        return res.end();
      }

      // Behind Coolify/Traefik/nginx the public scheme is HTTPS while the
      // app itself sees HTTP — trust the forwarded proto so rewritten
      // playlist URLs keep the correct scheme (no mixed-content breaks).
      const fwdHost = req.headers["x-forwarded-host"];
      const host = (typeof fwdHost === "string" && fwdHost ? fwdHost : req.headers.host) || "localhost";
      const fwdProto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
      const selfOrigin = `${fwdProto}://${host}`;

      // health / docs
      let path = req.url;
      if (path === "/" || path === "/health") {
        const profiles = Object.fromEntries(
          Object.entries(PROFILES).map(([k, v]) => [k, v.label]),
        );
        const body = JSON.stringify(
          {
            ok: true,
            service: "vps-proxy-pool",
            node: process.version,
            defaultProfile: DEFAULT_PROFILE,
            outboundProxy: dispatcher ? "on" : "off",
            profiles,
            usage: [
              "/{profile}/https://upstream.com/path   (plain mode)",
              "/{profile}/v1.<iv>.<data>               (encrypted mode)",
              `/https://upstream.com/path              (plain mode, default profile: ${DEFAULT_PROFILE})`,
              `/v1.<iv>.<data>                         (encrypted mode, default profile: ${DEFAULT_PROFILE})`,
            ],
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

      // strip leading slash
      let rest = path.replace(/^\//, "");

      // optional profile segment — /{profile}/...
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
        // first segment was clearly meant as a profile but doesn't exist
        return plain(
          res,
          404,
          `Unknown profile "${m[1]}". Available: ${Object.keys(PROFILES).join(", ")}`,
        );
      }
      const profile = PROFILES[profileName];
      const selfBase = `${selfOrigin}/${profileName}`;

      // ---- ENCRYPTED MODE: v1.<iv>.<data> (from any API's ?data=en) ----
      if (TOKEN_RE.test(rest)) {
        let target;
        try {
          target = new URL(await decryptToken(rest));
        } catch (e) {
          return plain(res, 403, "Invalid or tampered token.");
        }
        await proxyRequest(req, res, target, profile, true, selfBase);
        log(req, res, profileName, "encrypted", started);
        return;
      }

      // ---- PLAIN MODE: https://target.com/path (unchanged behavior) ----
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

      await proxyRequest(req, res, targetUrl, profile, false, selfBase);
      log(req, res, profileName, "plain", started);
    } catch (err) {
      if (!res.headersSent) {
        plain(res, 500, "Error: " + (err && err.message ? err.message : String(err)));
      } else {
        res.destroy();
      }
    }
  });
}

function log(req, res, profile, mode, started) {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${profile}/${mode} -> ${res.statusCode} (${Date.now() - started}ms)`,
  );
}

/* ------------------------------------------------------------------ */

if (require.main === module) {
  const server = createServer();
  server.listen(PORT, HOST, () => {
    console.log(`[vps-proxy-pool] listening on http://${HOST}:${PORT}`);
    console.log(`[vps-proxy-pool] default profile: ${DEFAULT_PROFILE}`);
    for (const [k, v] of Object.entries(PROFILES)) {
      console.log(`  /${k}/  ->  ${v.label}`);
    }
    console.log(`[vps-proxy-pool] secret: ${TOKEN_SECRET.slice(0, 8)}… (shared with all APIs)`);
  });

  // graceful shutdown (systemd / pm2 / docker friendly)
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 3000).unref();
    });
  }
}

module.exports = { createServer, PROFILES, encryptToken, decryptToken, TOKEN_RE };
