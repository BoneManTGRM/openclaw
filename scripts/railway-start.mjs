// scripts/railway-start.mjs
// Railway friendly OpenClaw launcher and proxy.
//
// What this file does
// - Starts OpenClaw gateway on an internal port (default 8081) and proxies Railway PORT to it.
// - Optionally lets OpenClaw bind directly to Railway PORT when OPENCLAW_LISTEN_ON_EXTERNAL=1.
// - Writes a safe OpenClaw config (openclaw.json + config.json) with gateway.port and gateway.trustedProxies.
// - Prevents pairing-required loops on Railway by sanitizing proxy-derived headers in selfSanitize mode.
// - Fixes loopback Host header mismatch that can flip OpenClaw into "remote" mode.
// - Optionally writes auth-profiles.json from env vars or ANTHROPIC_API_KEY / OPENAI_API_KEY.
//
// Key improvements in this update
// 1) FIX: Token header name compatibility for new OpenClaw builds.
//    OpenClaw now prefers Authorization: Bearer <token> and X-Clawdbot-Token header.
//    Your previous script injected x-openclaw-token, which newer builds may ignore.
//    This revision injects BOTH Authorization and X-Clawdbot-Token (and keeps x-openclaw-token as compat).
// 2) Adaptive flag fallback: if OpenClaw does not support flags like --no-doctor or --allow-unconfigured,
//    we detect "unknown option" and restart without the offending flag.
// 3) Token injection is based on actual child token usage, not only OPENCLAW_ENFORCE_TOKEN_AUTH.
// 4) Readiness checks inject the token when the child is using token auth (and can auto-detect 401/403).
// 5) Proxy response headers are cleaned for hop-by-hop headers to avoid weirdness with some clients.
// 6) Hardening around remoteAddress formatting and forwarded header sanitization.
// 7) Safety: if enforce token auth is enabled but token is missing, auto disable it with a warning.
// 8) Fix tcpCheck: avoid false negatives by not failing on "close" after a successful connect.
// 9) Hardening: killChild only SIGKILL if still alive.
// 10) Cleanup: do not keep an idle interval around in external listen mode by default
//     (set OPENCLAW_EXTERNAL_WATCHDOG=1 if you want the external mode watchdog).
//
// IMPORTANT FIX ADDED HERE (most common Railway issue):
// - OpenClaw sometimes ignores OPENCLAW_STATE_DIR and reads config only from $HOME/.openclaw (or /home/node/.openclaw).
// - This script now mirrors config and auth-profiles into BOTH the chosen writable stateDir AND any writable "standard" dirs.
//   This prevents "proxy/trustedProxies/auth" fixes from silently not applying even though the script printed "wrote config".
//
// Applied updates in this revision
// - Mirror config/auth to standard dirs (HOME/.openclaw, /home/node/.openclaw, /data/.openclaw when writable)
// - Improve WS stability: setNoDelay(true) on both sockets after upgrade
// - Improve WS stability further: setNoDelay(true) on client socket as early as possible
// - Harden destroyBoth(): attempt end() before destroy() to avoid stuck half-open sockets on mobile
// - Add gentle delays between end() and destroy() to reduce Safari "closed before connect" incidence
// - Optional: OPENCLAW_WS_FORCE_LOCAL_ORIGIN=1 can rewrite Origin to local in loopback upstream
//
// FIX FOR YOUR CURRENT LOGS (Loopback connection with non-local Host header)
// The fix remains: for WS upgrades, force upstream Host to local (127.0.0.1:8081) by default, and ALSO send a minimal
// rebuilt set of x-forwarded-* and x-real-ip so OpenClaw can still understand the true external origin.
// Env toggle (default ON):
//   OPENCLAW_WS_FORCE_LOCAL_HOST=1
//
// Existing env toggle (still honored):
//   OPENCLAW_WS_STRIP_PROXY_HEADERS=1
// In this revision, "strip" means: remove arbitrary proxy headers, then rebuild the minimal safe set.

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";

console.log("[railway-start] starting");

function uniq(arr) {
  return Array.from(new Set((arr || []).filter(Boolean)));
}

function envBool(name, defaultValue = false) {
  const v = String(process.env[name] || "").trim().toLowerCase();
  if (!v) return defaultValue;
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

function envInt(name, fallback) {
  const raw = String(process.env[name] ?? "").trim();
  if (raw.length === 0) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function envStr(name, fallback = "") {
  const v = String(process.env[name] || "").trim();
  return v || fallback;
}

function readJsonIfExists(p) {
  try {
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (e) {
    console.log(`[railway-start] could not read ${p}: ${e?.message || e}`);
    return null;
  }
}

function safeMkdir(dir) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    return true;
  } catch (e) {
    console.log(`[railway-start] mkdir failed ${dir}: ${e?.message || e}`);
    return false;
  }
}

function safeWriteJson(p, obj) {
  try {
    fs.writeFileSync(p, JSON.stringify(obj, null, 2), "utf8");
    console.log(`[railway-start] wrote ${p}`);
    return true;
  } catch (e) {
    console.log(`[railway-start] write failed ${p}: ${e?.message || e}`);
    return false;
  }
}

function safeWriteText(p, text) {
  try {
    fs.writeFileSync(p, String(text ?? ""), "utf8");
    console.log(`[railway-start] wrote ${p}`);
    return true;
  } catch (e) {
    console.log(`[railway-start] write failed ${p}: ${e?.message || e}`);
    return false;
  }
}

function canWriteDir(dir) {
  try {
    safeMkdir(dir);
    const test = path.join(dir, `.write-test-${Date.now()}.tmp`);
    fs.writeFileSync(test, "ok", "utf8");
    fs.unlinkSync(test);
    return true;
  } catch {
    return false;
  }
}

function parseTrustedProxies() {
  const trustAll = envBool("OPENCLAW_TRUST_ALL_PROXIES", false);
  if (trustAll) return ["0.0.0.0/0", "::/0"];

  const override = String(process.env.OPENCLAW_TRUSTED_PROXIES || "").trim();

  const base = [
    "100.64.0.0/10",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.1/32",
    "127.0.0.1",
    "::1/128",
    "::1",
  ];

  const extra = override
    ? override
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  return uniq([...base, ...extra]);
}

function tcpCheck(host, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    let doneCalled = false;
    let connected = false;

    const done = (ok) => {
      if (doneCalled) return;
      doneCalled = true;
      try {
        sock.destroy();
      } catch {}
      resolve(ok);
    };

    sock.setTimeout(timeoutMs);

    sock.on("connect", () => {
      connected = true;
      done(true);
    });

    sock.on("timeout", () => done(false));
    sock.on("error", () => done(false));

    // Important: do not fail on close if we already connected successfully.
    sock.on("close", () => {
      if (!connected) done(false);
    });
  });
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function hasWorkingLsof() {
  try {
    const res = spawnSync("lsof", ["-v"], { stdio: "ignore" });
    if (res.error) return false;
    return res.status === 0 || res.status === 1;
  } catch {
    return false;
  }
}

function parseHostOnly(hostHeader) {
  const raw = String(hostHeader || "").trim();
  if (!raw) return "";
  if (raw.startsWith("[")) {
    const end = raw.indexOf("]");
    if (end > 0) return raw.slice(0, end + 1).toLowerCase();
    return raw.toLowerCase();
  }
  const idx = raw.indexOf(":");
  if (idx >= 0) return raw.slice(0, idx).toLowerCase();
  return raw.toLowerCase();
}

function isLoopbackHost(h) {
  const s = String(h || "").trim().toLowerCase();
  if (!s) return false;
  if (s === "127.0.0.1") return true;
  if (s === "localhost") return true;
  if (s === "::1") return true;
  return false;
}

function isLocalHostHeader(hostHeader) {
  const hostOnly = parseHostOnly(hostHeader);
  return (
    hostOnly === "127.0.0.1" ||
    hostOnly === "localhost" ||
    hostOnly === "[::1]" ||
    hostOnly === "::1"
  );
}

// IPv6-safe local Host header builder
function buildLocalHostHeader(hostForUpstream, portForUpstream) {
  const hh = String(hostForUpstream || "").trim();
  if (!hh) return `127.0.0.1:${portForUpstream}`;

  if (hh.startsWith("[") && hh.includes("]")) return `${hh}:${portForUpstream}`;

  if (hh.includes(":") && !hh.includes(".")) return `[${hh}]:${portForUpstream}`;

  if (hh.includes(":")) return hh;

  return `${hh}:${portForUpstream}`;
}

// Basic shell-style split with quotes, for OPENCLAW_CMD only.
function shellSplit(cmdline) {
  const s = String(cmdline || "").trim();
  if (!s) return [];
  const out = [];
  let cur = "";
  let q = null;
  let esc = false;

  for (let i = 0; i < s.length; i++) {
    const ch = s[i];

    if (esc) {
      cur += ch;
      esc = false;
      continue;
    }

    if (q === '"') {
      if (ch === "\\") {
        esc = true;
        continue;
      }
      if (ch === '"') {
        q = null;
        continue;
      }
      cur += ch;
      continue;
    }

    if (q === "'") {
      if (ch === "'") {
        q = null;
        continue;
      }
      cur += ch;
      continue;
    }

    if (ch === '"' || ch === "'") {
      q = ch;
      continue;
    }

    if (/\s/.test(ch)) {
      if (cur.length) out.push(cur), (cur = "");
      continue;
    }

    cur += ch;
  }

  if (cur.length) out.push(cur);

  return out;
}

function shQuoteArg(a) {
  const s = String(a ?? "");
  if (s.length === 0) return "''";
  if (/^[A-Za-z0-9_./:@-]+$/.test(s)) return s;
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

function shJoin(cmd, args) {
  return [cmd, ...(args || [])].map(shQuoteArg).join(" ");
}

function headerValueToString(v) {
  if (Array.isArray(v)) return v.map((x) => String(x)).join(", ");
  if (v == null) return "";
  return String(v);
}

function headersToLines(headers) {
  const out = [];
  for (const [k, v] of Object.entries(headers || {})) {
    const sv = headerValueToString(v);
    if (!sv) continue;
    out.push(`${k}: ${sv}`);
  }
  return out;
}

function tokenFingerprint(tok) {
  const t = String(tok || "");
  if (!t) return { present: false, len: 0, sha256_8: "" };
  const hex = crypto.createHash("sha256").update(t).digest("hex");
  return { present: true, len: t.length, sha256_8: hex.slice(0, 8) };
}

function parseReadyExpect(expectRaw) {
  const raw = String(expectRaw || "").trim().toLowerCase();
  if (!raw) return { mode: "exact", exact: new Set(["200"]) };
  if (raw === "2xx") return { mode: "2xx" };
  if (raw === "any") return { mode: "any" };

  const parts = raw
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

  if (parts.length === 0) return { mode: "exact", exact: new Set(["200"]) };
  return { mode: "exact", exact: new Set(parts) };
}

function parseReadyFallbackPaths(raw) {
  const s = String(raw || "").trim();
  if (!s) return ["/", "/ready"];
  const parts = s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .map((p) => (p.startsWith("/") ? p : `/${p}`));
  return parts.length ? parts : ["/", "/ready"];
}

function matchesReadyExpect(statusCode, expectSpec) {
  const code = Number(statusCode);
  if (!Number.isFinite(code)) return false;

  if (expectSpec.mode === "2xx") return code >= 200 && code <= 299;
  if (expectSpec.mode === "any") return code >= 200 && code <= 499;

  const str = String(code);
  return expectSpec.exact?.has(str) || false;
}

// Railway port (public)
const externalPort = envInt("PORT", 8080);

// Internal port for OpenClaw when proxying (default)
const internalPortDefault = envInt("OPENCLAW_INTERNAL_PORT", 8081);

// If OPENCLAW_LISTEN_ON_EXTERNAL=1, OpenClaw binds to externalPort.
const openclawListenOnExternal = envBool("OPENCLAW_LISTEN_ON_EXTERNAL", false);

const internalPort = openclawListenOnExternal ? externalPort : internalPortDefault;

const token = envStr("OPENCLAW_GATEWAY_TOKEN", "");

// Token auth requested
let enforceTokenAuth = envBool("OPENCLAW_ENFORCE_TOKEN_AUTH", false);

// Inject gateway token into upstream requests
let injectGatewayTokenHeaders = envBool("OPENCLAW_INJECT_GATEWAY_TOKEN_HEADERS", true);

// Optional compat: keep extra token header(s) for older builds (default ON for safety)
const tokenHeaderCompat = envBool("OPENCLAW_TOKEN_HEADER_COMPAT", true);
// Optional legacy header (default OFF): x-openclaw-gateway-token
const legacyGatewayTokenHeader = envBool("OPENCLAW_LEGACY_GATEWAY_TOKEN_HEADER", false);

// Auto-heal when OpenClaw complains auth token missing
const autoPassTokenOnAuthError = envBool("OPENCLAW_AUTO_PASS_TOKEN_ON_AUTH_ERROR", true);

// If token auth is not enforced, default to NOT passing OPENCLAW_GATEWAY_TOKEN into the child.
let passGatewayTokenToChild =
  enforceTokenAuth || envBool("OPENCLAW_PASS_GATEWAY_TOKEN_TO_CHILD", false);

// Runtime: whether the current child is actually using token auth.
// This is used to decide whether to inject token headers into upstream requests.
// It can be auto-detected via readiness 401/403 or logs.
let childUsesTokenAuth = !!(enforceTokenAuth || passGatewayTokenToChild);

// Safety: if enforceTokenAuth was requested but token is missing, disable it
if (enforceTokenAuth && !token) {
  enforceTokenAuth = false;
  console.log(
    "[railway-start] warning: OPENCLAW_ENFORCE_TOKEN_AUTH=1 but OPENCLAW_GATEWAY_TOKEN is empty"
  );
  console.log("[railway-start] warning: disabling enforceTokenAuth to avoid broken auth config");

  passGatewayTokenToChild = envBool("OPENCLAW_PASS_GATEWAY_TOKEN_TO_CHILD", false);
  childUsesTokenAuth = !!passGatewayTokenToChild;
}

// Self sanitize config to a strict minimal object that cannot contain unknown keys.
const selfSanitize = envBool("OPENCLAW_SELF_SANITIZE", true);

let startupTimeoutMs = envInt("OPENCLAW_STARTUP_TIMEOUT_MS", 120000);
startupTimeoutMs = clamp(startupTimeoutMs, 15000, 600000);

const watchdogIntervalMs = envInt("OPENCLAW_WATCHDOG_INTERVAL_MS", 8000);
const proxyTimeoutMs = envInt("OPENCLAW_PROXY_TIMEOUT_MS", 60000);

// External mode watchdog is OFF by default
const externalWatchdogEnabled = envBool("OPENCLAW_EXTERNAL_WATCHDOG", false);

// Readiness checks
const readyCheckMode =
  envStr("OPENCLAW_READY_CHECK_MODE", "http").toLowerCase() === "tcp" ? "tcp" : "http";
const readyPath = envStr("OPENCLAW_READY_PATH", "/health") || "/health";
const readyFallbackPaths = parseReadyFallbackPaths(
  envStr("OPENCLAW_READY_FALLBACK_PATHS", "/,/ready")
);
const readyExpectRaw = String(envStr("OPENCLAW_READY_EXPECT", "200")).trim() || "200";
const readyExpectSpec = parseReadyExpect(readyExpectRaw);

let readyTimeoutMs = envInt("OPENCLAW_READY_TIMEOUT_MS", 1200);
readyTimeoutMs = clamp(readyTimeoutMs, 250, 8000);

// Upstream protocol for proxy mode
const upstreamProtocol =
  envStr("OPENCLAW_UPSTREAM_PROTOCOL", "http").toLowerCase() === "https" ? "https" : "http";
const upstreamHost = envStr("OPENCLAW_UPSTREAM_HOST", "127.0.0.1");

// Hoist env bools that were previously read in hot paths
const upstreamInsecure = envBool("OPENCLAW_UPSTREAM_INSECURE", false);

// Optional: override forwarded host/proto if you want hardcoding.
const forwardedProtoOverride = envStr("OPENCLAW_FORWARDED_PROTO", "");
const forwardedHostOverride = envStr("OPENCLAW_FORWARDED_HOST", "");

// Optional: if set, force the Host header sent upstream (rare)
const upstreamHostHeaderOverride = envStr("OPENCLAW_UPSTREAM_HOST_HEADER", "");

// If true, rewrite Host to local loopback when upstreamHost is loopback.
const upstreamForceLocalHostHeader = envBool("OPENCLAW_UPSTREAM_FORCE_LOCAL_HOST", false);

// WS: strip arbitrary proxy-derived headers on upgrade (default ON)
const wsStripProxyHeaders = envBool("OPENCLAW_WS_STRIP_PROXY_HEADERS", true);

// WS: force upstream Host to local loopback (default ON, fixes your log)
const wsForceLocalHostHeader = envBool("OPENCLAW_WS_FORCE_LOCAL_HOST", true);

// Optional: if enabled, rewrite Origin to local when upstream is loopback
const wsForceLocalOrigin = envBool("OPENCLAW_WS_FORCE_LOCAL_ORIGIN", false);

// OpenClaw expects bind MODEs here, not IPs.
const bindPrimaryEnv = envStr("OPENCLAW_BIND", "loopback");
const bindFallbackEnv = envStr("OPENCLAW_BIND_FALLBACK", "lan");

// If OpenClaw is the public listener, it cannot bind loopback on Railway
const bindPrimary = openclawListenOnExternal ? "lan" : bindPrimaryEnv;
const bindFallback = openclawListenOnExternal ? "lan" : bindFallbackEnv;

const useShellForLocalBin = envBool("OPENCLAW_SHELL_LOCAL_BIN", true);

// Optional: enforce a token on inbound requests to the wrapper proxy.
const enforceProxyToken = envBool("OPENCLAW_PROXY_ENFORCE_TOKEN", false);

// Proxy enabled by default, disabled automatically if OpenClaw is listening on external.
const proxyEnabled = envBool("OPENCLAW_PROXY_ENABLED", !openclawListenOnExternal);

// Use --force only if explicitly requested AND lsof exists.
const forceRequested = envBool("OPENCLAW_FORCE", false);
const forceEnabled = forceRequested && hasWorkingLsof();

// Flags that may not exist on older builds
let flagAllowUnconfigured = envBool("OPENCLAW_ALLOW_UNCONFIGURED", true);
let flagNoDoctor = envBool("OPENCLAW_NO_DOCTOR", true);

// Optional: enforce a strict retry without unknown flags by setting OPENCLAW_DISABLE_FLAG_AUTOFALLBACK=1
const disableFlagAutofallback = envBool("OPENCLAW_DISABLE_FLAG_AUTOFALLBACK", false);

// WS gentle close delay (helps iOS Safari)
let wsCloseDelayMs = envInt("OPENCLAW_WS_CLOSE_DELAY_MS", 120);
wsCloseDelayMs = clamp(wsCloseDelayMs, 0, 1500);

// Simplified stateDir selection
const candidates = [
  process.env.OPENCLAW_STATE_DIR,
  "/data/.openclaw",
  "/home/node/.openclaw",
  "/tmp/.openclaw",
].filter(Boolean);

let stateDir = "/tmp/.openclaw";
for (const dir of candidates) {
  if (canWriteDir(dir)) {
    stateDir = dir;
    break;
  }
}

const tokenFp = tokenFingerprint(token);

console.log("[railway-start] external PORT =", externalPort);
console.log("[railway-start] internal OpenClaw port =", internalPort);
console.log("[railway-start] proxyEnabled =", proxyEnabled ? "yes" : "no");
console.log("[railway-start] openclawListenOnExternal =", openclawListenOnExternal ? "yes" : "no");
console.log("[railway-start] chosen stateDir =", stateDir);
console.log("[railway-start] token present =", token ? "yes" : "no");
console.log(
  "[railway-start] token fingerprint =",
  tokenFp.present ? `${tokenFp.sha256_8} (len ${tokenFp.len})` : "none"
);
console.log("[railway-start] enforce gateway token auth =", enforceTokenAuth ? "yes" : "no");
console.log("[railway-start] inject gateway token headers =", injectGatewayTokenHeaders ? "yes" : "no");
console.log("[railway-start] pass gateway token to child =", passGatewayTokenToChild ? "yes" : "no");
console.log("[railway-start] childUsesTokenAuth =", childUsesTokenAuth ? "yes" : "no");
console.log("[railway-start] tokenHeaderCompat =", tokenHeaderCompat ? "yes" : "no");
console.log("[railway-start] legacyGatewayTokenHeader =", legacyGatewayTokenHeader ? "yes" : "no");
if (passGatewayTokenToChild && !token) {
  console.log("[railway-start] warning: passGatewayTokenToChild=1 but token is empty");
}
console.log("[railway-start] autoPassTokenOnAuthError =", autoPassTokenOnAuthError ? "yes" : "no");
console.log("[railway-start] enforce proxy token =", enforceProxyToken ? "yes" : "no");
console.log("[railway-start] selfSanitize =", selfSanitize ? "yes" : "no");
console.log("[railway-start] startupTimeoutMs =", startupTimeoutMs);
console.log("[railway-start] bindPrimary =", bindPrimary, "bindFallback =", bindFallback);
console.log("[railway-start] OPENCLAW_SHELL_LOCAL_BIN =", useShellForLocalBin ? "yes" : "no");
console.log("[railway-start] OpenClaw force requested =", forceRequested ? "yes" : "no");
console.log("[railway-start] OpenClaw force enabled =", forceEnabled ? "yes" : "no");
console.log("[railway-start] OpenClaw flagAllowUnconfigured =", flagAllowUnconfigured ? "yes" : "no");
console.log("[railway-start] OpenClaw flagNoDoctor =", flagNoDoctor ? "yes" : "no");
console.log("[railway-start] upstream =", `${upstreamProtocol}://${upstreamHost}:${internalPort}`);
console.log(
  "[railway-start] readyCheckMode =",
  readyCheckMode,
  "readyPath =",
  readyPath,
  "readyFallbackPaths =",
  readyFallbackPaths.join(","),
  "readyExpect =",
  readyExpectRaw
);
console.log("[railway-start] upstreamForceLocalHostHeader =", upstreamForceLocalHostHeader ? "yes" : "no");
console.log("[railway-start] wsCloseDelayMs =", wsCloseDelayMs);
console.log("[railway-start] wsStripProxyHeaders =", wsStripProxyHeaders ? "yes" : "no");
console.log("[railway-start] wsForceLocalHostHeader =", wsForceLocalHostHeader ? "yes" : "no");
console.log("[railway-start] wsForceLocalOrigin =", wsForceLocalOrigin ? "yes" : "no");

if (openclawListenOnExternal) {
  console.log("[railway-start] warning: OPENCLAW_LISTEN_ON_EXTERNAL=1 disables wrapper server");
  console.log("[railway-start] recommended default on Railway is proxy mode (OPENCLAW_LISTEN_ON_EXTERNAL=0)");
  console.log("[railway-start] external watchdog enabled =", externalWatchdogEnabled ? "yes" : "no");
}

safeMkdir(stateDir);

// NEW: build a set of "standard" dirs OpenClaw may read from, and mirror config there if writable.
function computeMirrorDirs(primaryDir) {
  const out = [];

  const home = String(process.env.HOME || "").trim();
  if (home) out.push(path.join(home, ".openclaw"));

  // Common Railway/Node images
  out.push("/home/node/.openclaw");
  out.push("/data/.openclaw");

  // Include primary
  out.push(primaryDir);

  // Only keep dirs we can write
  const writable = [];
  for (const d of uniq(out)) {
    if (canWriteDir(d)) writable.push(d);
  }
  return uniq(writable);
}

const mirrorDirs = computeMirrorDirs(stateDir);

console.log("[railway-start] config mirrorDirs =", mirrorDirs.join(", "));

const configAName = "openclaw.json";
const configBName = "config.json";

// Read existing config (if any) then sanitize.
const existing =
  readJsonIfExists(path.join(stateDir, configAName)) ||
  readJsonIfExists(path.join(stateDir, configBName)) ||
  // Also try standard dirs in case stateDir differs from where OpenClaw last wrote
  (mirrorDirs
    .map((d) => readJsonIfExists(path.join(d, configAName)) || readJsonIfExists(path.join(d, configBName)))
    .find(Boolean) ||
    {}) ||
  {};

const existingGateway =
  typeof existing?.gateway === "object" && existing.gateway ? existing.gateway : {};

function buildSanitizedConfig() {
  const cfg = {};
  cfg.gateway = {};

  cfg.gateway.port = Number(internalPort);

  const trusted = uniq([
    ...(Array.isArray(existingGateway.trustedProxies) ? existingGateway.trustedProxies : []),
    ...parseTrustedProxies(),
  ]);
  cfg.gateway.trustedProxies = trusted;

  if (enforceTokenAuth && token) {
    cfg.gateway.auth = { mode: "token", token };
    console.log("[railway-start] gateway auth enabled (token)");
  } else {
    delete cfg.gateway.auth;
    console.log("[railway-start] gateway auth not configured");
  }

  return { cfg, trusted };
}

function buildCompatConfig() {
  const base = typeof existing === "object" && existing ? existing : {};
  base.gateway = typeof base.gateway === "object" && base.gateway ? base.gateway : {};

  base.gateway.port = Number(internalPort);

  const trusted = uniq([
    ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
    ...parseTrustedProxies(),
  ]);
  base.gateway.trustedProxies = trusted;

  delete base.trustProxy;
  delete base.trustedProxies;
  if (base.gateway) {
    delete base.gateway.trustProxy;
    delete base.gateway.trustProxies;
    delete base.gateway.pairingRequired;
  }

  if (enforceTokenAuth && token) {
    base.gateway.auth = base.gateway.auth || {};
    base.gateway.auth.mode = "token";
    base.gateway.auth.token = token;
    console.log("[railway-start] gateway auth enabled (token)");
  } else {
    delete base.gateway.auth;
    console.log("[railway-start] gateway auth not configured");
  }

  return { cfg: base, trusted };
}

let trusted = [];
let configToWrite = null;

if (selfSanitize) {
  const built = buildSanitizedConfig();
  configToWrite = built.cfg;
  trusted = built.trusted;

  const existingRootKeys = Object.keys(typeof existing === "object" && existing ? existing : {});
  const keptRootKeys = ["gateway"];
  const droppedRoot = existingRootKeys.filter((k) => !keptRootKeys.includes(k));
  if (droppedRoot.length) {
    console.log("[railway-start] selfSanitize: dropped root keys:", droppedRoot.join(", "));
  }

  const existingGwKeys = Object.keys(existingGateway);
  const keptGwKeys = ["port", "trustedProxies", "auth"];
  const droppedGw = existingGwKeys.filter((k) => !keptGwKeys.includes(k));
  if (droppedGw.length) {
    console.log("[railway-start] selfSanitize: dropped gateway keys:", droppedGw.join(", "));
  }
} else {
  const built = buildCompatConfig();
  configToWrite = built.cfg;
  trusted = built.trusted;
}

// NEW: write config into all mirrorDirs so OpenClaw cannot "miss" the config.
for (const d of mirrorDirs) {
  safeMkdir(d);
  safeWriteJson(path.join(d, configAName), configToWrite);
  safeWriteJson(path.join(d, configBName), configToWrite);
}

// Optional: write OpenClaw agent auth store if provided.
(function writeAuthProfilesIfProvided() {
  const jsonRaw = envStr("OPENCLAW_AUTH_PROFILES_JSON", "").trim();
  const b64 = envStr("OPENCLAW_AUTH_PROFILES_B64", "").trim();
  const openaiKey = envStr("OPENAI_API_KEY", "").trim();
  const anthropicKey = envStr("ANTHROPIC_API_KEY", "").trim();

  if (!jsonRaw && !b64 && !openaiKey && !anthropicKey) {
    console.log(
      "[railway-start] no auth profiles env vars found (OPENCLAW_AUTH_PROFILES_JSON, OPENCLAW_AUTH_PROFILES_B64, OPENAI_API_KEY, ANTHROPIC_API_KEY)"
    );
    return;
  }

  // NEW: mirror auth-profiles into every mirrorDir as well.
  for (const baseDir of mirrorDirs) {
    const agentAuthDir = path.join(baseDir, "agents", "main", "agent");
    const authPath = path.join(agentAuthDir, "auth-profiles.json");
    safeMkdir(agentAuthDir);

    if (jsonRaw) {
      console.log("[railway-start] writing auth-profiles.json from OPENCLAW_AUTH_PROFILES_JSON to", authPath);
      safeWriteText(authPath, jsonRaw);
      continue;
    }

    if (b64) {
      console.log("[railway-start] writing auth-profiles.json from OPENCLAW_AUTH_PROFILES_B64 to", authPath);
      try {
        const buf = Buffer.from(b64, "base64");
        safeWriteText(authPath, buf.toString("utf8"));
      } catch (e) {
        console.log(`[railway-start] failed to decode OPENCLAW_AUTH_PROFILES_B64: ${e?.message || e}`);
      }
      continue;
    }

    const authObj = {};
    if (openaiKey) authObj.openai = { apiKey: openaiKey };
    if (anthropicKey) authObj.anthropic = { apiKey: anthropicKey };

    console.log("[railway-start] auto-generating auth-profiles.json from API key env vars to", authPath);
    safeWriteJson(authPath, authObj);
  }
})();

// -----------------
// OpenClaw process state
// -----------------
let claw = null;
let clawStarting = false;
let clawReady = false;

let restartAttempt = 0;
let startLoopId = 0;
let restartScheduled = false;

const MAX_LOG_LINES = envInt("OPENCLAW_LOG_RING_MAX", 300);
const outRing = [];
const errRing = [];

function pushRing(arr, line) {
  arr.push(line);
  while (arr.length > MAX_LOG_LINES) arr.shift();
}

function dumpRing(label, arr) {
  if (!arr.length) return;
  console.log(label, "last", arr.length, "lines");
  for (const ln of arr) console.log(label, ln);
}

function computeBackoffMs(attempt) {
  const a = clamp(attempt, 0, 8);
  const baseMs = 800 * Math.pow(1.7, a);
  const jitter = Math.floor(Math.random() * 350);
  return clamp(Math.floor(baseMs + jitter), 800, 20000);
}

function killChild(child) {
  if (!child) return;
  try {
    child.kill("SIGTERM");
  } catch {}

  setTimeout(() => {
    try {
      if (child.exitCode == null && child.signalCode == null) {
        child.kill("SIGKILL");
      }
    } catch {}
  }, 2500);
}

function scheduleRestart(waitMs) {
  if (restartScheduled) return;
  restartScheduled = true;
  console.log("[railway-start] restarting in", waitMs, "ms");
  setTimeout(() => {
    restartScheduled = false;
    startOpenClawLoop();
  }, waitMs);
}

function resolveOpenClawCommand() {
  const override = envStr("OPENCLAW_CMD", "").trim();
  if (override) {
    const parts = shellSplit(override);
    console.log("[railway-start] using OPENCLAW_CMD override:", parts.join(" "));
    if (parts.length === 0) return null;
    return { kind: "direct", cmd: parts[0], argsPrefix: parts.slice(1) };
  }

  const localBin = path.resolve("node_modules", ".bin", "openclaw");
  if (fs.existsSync(localBin)) {
    console.log("[railway-start] found local openclaw bin:", localBin);
    return { kind: "localbin", cmd: localBin, argsPrefix: [] };
  }

  const entryMjs = path.resolve("openclaw.mjs");
  if (fs.existsSync(entryMjs)) {
    console.log("[railway-start] found openclaw.mjs:", entryMjs);
    return { kind: "node", cmd: process.execPath, argsPrefix: [entryMjs] };
  }

  const distEntry = path.resolve("dist", "index.js");
  if (fs.existsSync(distEntry)) {
    console.log("[railway-start] found dist/index.js:", distEntry);
    return { kind: "node", cmd: process.execPath, argsPrefix: [distEntry] };
  }

  return null;
}

function buildOpenClawArgs(bindMode) {
  const args = ["gateway", "--bind", String(bindMode), "--port", String(internalPort)];

  if (flagAllowUnconfigured) args.push("--allow-unconfigured");

  if (passGatewayTokenToChild) {
    if (token) {
      args.push("--token", token);
    } else {
      console.log(
        "[railway-start] warning: passGatewayTokenToChild=1 but token is empty, skipping --token"
      );
    }
  }

  if (forceEnabled) {
    args.push("--force");
  } else if (forceRequested && !forceEnabled) {
    console.log("[railway-start] OPENCLAW_FORCE=1 requested but lsof is missing, skipping --force");
  }

  if (flagNoDoctor) args.push("--no-doctor");

  return args;
}

function currentBindForAttempt(attempt) {
  return attempt >= 2 ? bindFallback : bindPrimary;
}

function spawnOpenClawProcess(bindMode) {
  const childEnv = { ...process.env };

  // Primary state dir
  childEnv.OPENCLAW_STATE_DIR = stateDir;

  // Also provide a couple of common alias env vars (harmless if ignored)
  // This helps forks/builds that look for "config dir" rather than "state dir".
  childEnv.OPENCLAW_CONFIG_DIR = stateDir;
  childEnv.OPENCLAW_HOME_DIR = stateDir;

  if (passGatewayTokenToChild && token) {
    childEnv.OPENCLAW_GATEWAY_TOKEN = token;
  }

  if (!passGatewayTokenToChild) {
    delete childEnv.OPENCLAW_GATEWAY_TOKEN;
    delete childEnv.OPENCLAW_ENFORCE_TOKEN_AUTH;
  }

  const resolved = resolveOpenClawCommand();
  if (!resolved) {
    throw new Error(
      "Could not find OpenClaw entry. Missing node_modules/.bin/openclaw, openclaw.mjs, and dist/index.js."
    );
  }

  const args = [...resolved.argsPrefix, ...buildOpenClawArgs(bindMode)];

  // Update runtime auth mode based on the actual args we are about to use.
  // If args include "--token", the child will enforce token auth.
  childUsesTokenAuth = args.includes("--token") && !!token ? true : !!enforceTokenAuth;

  if (resolved.kind === "localbin" && useShellForLocalBin) {
    const cmdLine = shJoin(resolved.cmd, args);
    console.log("[railway-start] exec shell:", cmdLine);
    return spawn(cmdLine, {
      stdio: ["ignore", "pipe", "pipe"],
      env: childEnv,
      shell: true,
    });
  }

  console.log("[railway-start] exec:", [resolved.cmd, ...args].join(" "));
  return spawn(resolved.cmd, args, { stdio: ["ignore", "pipe", "pipe"], env: childEnv });
}

async function isPortReadyAnyHost() {
  const hosts = ["127.0.0.1", "localhost", "::1"];
  for (const h of hosts) {
    const ok = await tcpCheck(h, internalPort, 700);
    if (ok) return { ok: true, host: h };
  }
  return { ok: false, host: null };
}

const proxyAgentHttp = new http.Agent({
  keepAlive: true,
  maxSockets: envInt("OPENCLAW_PROXY_AGENT_MAX_SOCKETS", 80),
  maxFreeSockets: envInt("OPENCLAW_PROXY_AGENT_MAX_FREE_SOCKETS", 20),
});

const proxyAgentHttps = new https.Agent({
  keepAlive: true,
  maxSockets: envInt("OPENCLAW_PROXY_AGENT_MAX_SOCKETS", 80),
  maxFreeSockets: envInt("OPENCLAW_PROXY_AGENT_MAX_FREE_SOCKETS", 20),
});

function selectUpstreamClient() {
  return upstreamProtocol === "https" ? https : http;
}

function selectUpstreamAgent() {
  return upstreamProtocol === "https" ? proxyAgentHttps : proxyAgentHttp;
}

function shouldInjectGatewayToken() {
  if (!token) return false;
  if (!injectGatewayTokenHeaders) return false;
  return !!childUsesTokenAuth;
}

function applyGatewayTokenToHeaders(headers) {
  if (!shouldInjectGatewayToken()) return headers;
  const h = { ...(headers || {}) };

  // New preferred headers:
  h["authorization"] = `Bearer ${token}`;
  h["x-clawdbot-token"] = token;

  // Compat for older builds / forks:
  if (tokenHeaderCompat) {
    h["x-openclaw-token"] = token;
  }
  if (legacyGatewayTokenHeader) {
    h["x-openclaw-gateway-token"] = token;
  }

  return h;
}

// Force token headers regardless of childUsesTokenAuth (used only in detection paths).
function applyGatewayTokenToHeadersForced(headers) {
  if (!token) return headers;
  const h = { ...(headers || {}) };
  h["authorization"] = `Bearer ${token}`;
  h["x-clawdbot-token"] = token;
  if (tokenHeaderCompat) h["x-openclaw-token"] = token;
  if (legacyGatewayTokenHeader) h["x-openclaw-gateway-token"] = token;
  return h;
}

function safeHeaderValue(v) {
  const s = headerValueToString(v);
  return s.replace(/[\r\n]+/g, " ").trim();
}

async function httpReadyCheckOnce(pathToCheck, opts = {}) {
  const client = selectUpstreamClient();
  const agent = selectUpstreamAgent();

  let headers = {
    host: upstreamHostHeaderOverride || buildLocalHostHeader(upstreamHost, internalPort),
    accept: "text/plain,application/json,*/*",
    "user-agent": "railway-start-readycheck",
  };

  headers = opts.forceToken ? applyGatewayTokenToHeadersForced(headers) : applyGatewayTokenToHeaders(headers);

  const options = {
    agent,
    hostname: upstreamHost,
    port: internalPort,
    method: "GET",
    path: pathToCheck,
    headers,
    timeout: readyTimeoutMs,
  };

  if (upstreamProtocol === "https") {
    options.rejectUnauthorized = !upstreamInsecure;
  }

  return new Promise((resolve) => {
    const req = client.request(options, (res) => {
      const code = Number(res.statusCode || 0);
      res.resume();
      resolve({ ok: matchesReadyExpect(code, readyExpectSpec), code, path: pathToCheck });
    });
    req.on("timeout", () => {
      try {
        req.destroy(new Error("ready timeout"));
      } catch {}
      resolve({ ok: false, code: 0, path: pathToCheck, timeout: true });
    });
    req.on("error", () => resolve({ ok: false, code: 0, path: pathToCheck, error: true }));
    req.end();
  });
}

async function isOpenClawReadySignal() {
  if (readyCheckMode === "tcp") {
    const r = await isPortReadyAnyHost();
    return { ok: r.ok, detail: r };
  }

  const r = await isPortReadyAnyHost();
  if (!r.ok) return { ok: false, detail: r };

  // First try with current token injection decision.
  const first = await httpReadyCheckOnce(readyPath);
  if (first.ok) {
    return {
      ok: true,
      detail: { ...r, http: true, path: first.path, code: first.code, expect: readyExpectRaw },
    };
  }

  // Auto-detect token auth if upstream returns 401/403 and we have a token but are not currently injecting.
  // Then retry once with forced token headers.
  if ((first.code === 401 || first.code === 403) && token && injectGatewayTokenHeaders && !childUsesTokenAuth) {
    const forced = await httpReadyCheckOnce(readyPath, { forceToken: true });
    if (forced.ok) {
      childUsesTokenAuth = true;
      console.log("[railway-start] readiness detected token auth (401/403), enabling childUsesTokenAuth");
      return {
        ok: true,
        detail: { ...r, http: true, path: forced.path, code: forced.code, expect: readyExpectRaw, autoToken: true },
      };
    }
  }

  for (const p of readyFallbackPaths) {
    if (p === readyPath) continue;
    const chk = await httpReadyCheckOnce(p);
    if (chk.ok) {
      return {
        ok: true,
        detail: { ...r, http: true, path: chk.path, code: chk.code, expect: readyExpectRaw },
      };
    }

    if ((chk.code === 401 || chk.code === 403) && token && injectGatewayTokenHeaders && !childUsesTokenAuth) {
      const forced = await httpReadyCheckOnce(p, { forceToken: true });
      if (forced.ok) {
        childUsesTokenAuth = true;
        console.log("[railway-start] readiness detected token auth (401/403), enabling childUsesTokenAuth");
        return {
          ok: true,
          detail: { ...r, http: true, path: forced.path, code: forced.code, expect: readyExpectRaw, autoToken: true },
        };
      }
    }
  }

  return {
    ok: false,
    detail: {
      ...r,
      http: false,
      pathTried: [readyPath, ...readyFallbackPaths.filter((p) => p !== readyPath)],
      last: { path: first.path, code: first.code },
      expect: readyExpectRaw,
    },
  };
}

async function waitForOpenClawReady(timeoutMs, child) {
  const start = Date.now();
  const deadline = start + timeoutMs;

  await sleep(800);

  let lastLogAt = 0;

  while (Date.now() < deadline) {
    if (child && child.exitCode != null) {
      console.log("[railway-start] child already exited while waiting, exitCode =", child.exitCode);
      return false;
    }

    const sig = await isOpenClawReadySignal();
    if (sig.ok) {
      if (readyCheckMode === "tcp") {
        console.log("[railway-start] TCP ready on host", sig.detail.host, "port", internalPort);
      } else {
        console.log(
          "[railway-start] ready via HTTP",
          "host",
          sig.detail.host,
          "port",
          internalPort,
          "path",
          sig.detail.path,
          "code",
          sig.detail.code,
          "expect",
          readyExpectRaw
        );
      }
      return true;
    }

    const now = Date.now();
    if (now - lastLogAt > 5000) {
      lastLogAt = now;
      const elapsed = now - start;
      const remaining = Math.max(0, deadline - now);
      console.log(
        "[railway-start] waiting for readiness",
        "mode",
        readyCheckMode,
        "elapsed",
        elapsed,
        "ms",
        "remaining",
        remaining,
        "ms"
      );
    }

    await sleep(450);
  }

  return false;
}

function normalizeToken(s) {
  return String(s || "").trim();
}

function checkProxyToken(req) {
  if (!enforceProxyToken) return { ok: true, reason: "disabled" };
  if (!token) return { ok: false, reason: "missing-server-token" };

  const hdr =
    normalizeToken(req.headers["x-clawdbot-token"]) ||
    normalizeToken(req.headers["x-openclaw-token"]) ||
    normalizeToken(req.headers["x-openclaw-gateway-token"]) ||
    normalizeToken(req.headers["x-api-key"]) ||
    "";

  const auth = normalizeToken(req.headers["authorization"]);
  const bearer = auth.toLowerCase().startsWith("bearer ") ? normalizeToken(auth.slice(7)) : "";

  const got = hdr || bearer;
  if (!got) return { ok: false, reason: "missing-client-token" };
  if (got !== token) return { ok: false, reason: "bad-client-token" };

  return { ok: true, reason: "ok" };
}

function isPublicUiPath(url) {
  const u = String(url || "/");
  if (u === "/") return true;
  if (u === "/favicon.ico") return true;
  if (u === "/robots.txt") return true;
  if (u.startsWith("/assets/")) return true;
  if (u.startsWith("/static/")) return true;
  if (u.startsWith("/_next/")) return true;
  return false;
}

const PROXY_DERIVED_HEADERS = new Set([
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-forwarded-server",
  "x-forwarded-ssl",
  "x-forwarded-scheme",
  "x-forwarded-prefix",
  "x-original-forwarded-for",
  "x-real-ip",
  "true-client-ip",
  "cf-connecting-ip",
  "fastly-client-ip",
  "x-client-ip",
  "x-cluster-client-ip",
]);

function stripProxyDerivedHeaders(headersObj) {
  const out = {};
  for (const [k, v] of Object.entries(headersObj || {})) {
    const lk = String(k).toLowerCase();
    if (PROXY_DERIVED_HEADERS.has(lk)) continue;
    out[k] = v;
  }
  return out;
}

function pickHostHeaderForUpstream(req, xfHost) {
  if (upstreamHostHeaderOverride) return upstreamHostHeaderOverride;

  const inboundHost = req.headers?.host || "";
  const candidate = String(xfHost || inboundHost || "").trim();

  if (!candidate) return buildLocalHostHeader(upstreamHost, internalPort);

  if (!upstreamForceLocalHostHeader) return candidate;

  const inboundIsLocal = isLocalHostHeader(inboundHost);
  if (isLoopbackHost(upstreamHost) && !inboundIsLocal) {
    return buildLocalHostHeader(upstreamHost, internalPort);
  }

  return candidate;
}

function cleanRemoteAddr(addr) {
  let a = String(addr || "");
  if (!a) return "";
  if (a.startsWith("::ffff:")) a = a.slice("::ffff:".length);

  const zoneIdx = a.indexOf("%");
  if (zoneIdx >= 0) a = a.slice(0, zoneIdx);

  if (a.startsWith("[") && a.endsWith("]")) a = a.slice(1, -1);

  return a;
}

function safeProto(p) {
  const s = String(p || "").trim().toLowerCase();
  if (s === "https" || s === "http") return s;
  return "";
}

function safeHost(h) {
  const s = String(h || "").trim();
  if (!s) return "";
  return s.replace(/[\r\n]+/g, " ").trim();
}

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
]);

function buildForwardedHeaders(req, opts = {}) {
  const forWs = !!opts.forWs;

  const remoteAddr = cleanRemoteAddr(req.socket?.remoteAddress || "");

  const dash = String.fromCharCode(45);
  const H_XFF = "x" + dash + "forwarded" + dash + "for";
  const H_XFP = "x" + dash + "forwarded" + dash + "proto";
  const H_XFH = "x" + dash + "forwarded" + dash + "host";
  const H_XFPORT = "x" + dash + "forwarded" + dash + "port";
  const H_XREAL = "x" + dash + "real" + dash + "ip";

  const inboundXfp = safeProto(req.headers[H_XFP] || req.headers["x-forwarded-proto"]);
  const xfProto =
    safeProto(forwardedProtoOverride) || inboundXfp || (req.socket?.encrypted ? "https" : "http");

  const inboundXfh = safeHost(req.headers[H_XFH] || req.headers["x-forwarded-host"]);
  const inboundHost = safeHost(req.headers.host || "");
  const xfHost = safeHost(forwardedHostOverride) || inboundXfh || inboundHost || "";

  const cleaned = {};
  for (const [k, v] of Object.entries(req.headers || {})) {
    if (!HOP_BY_HOP.has(String(k).toLowerCase())) cleaned[k] = v;
  }

  delete cleaned.forwarded;

  const priorXff = req.headers[H_XFF] || req.headers["x-forwarded-for"];
  let xff = "";
  if (priorXff && remoteAddr) xff = `${safeHeaderValue(priorXff)}, ${remoteAddr}`;
  else if (priorXff) xff = safeHeaderValue(priorXff);
  else if (remoteAddr) xff = remoteAddr;

  // WS path: sanitize arbitrary proxy-derived headers, then rebuild minimal safe forwarded headers.
  // Also force upstream Host to local loopback by default when upstream is loopback.
  if (forWs && wsStripProxyHeaders) {
    const base = stripProxyDerivedHeaders(cleaned);

    const forcedHost =
      wsForceLocalHostHeader && isLoopbackHost(upstreamHost)
        ? buildLocalHostHeader(upstreamHost, internalPort)
        : pickHostHeaderForUpstream(req, xfHost);

    const rebuilt = {
      ...base,
      host: String(forcedHost || "").trim() || buildLocalHostHeader(upstreamHost, internalPort),
      [H_XFP]: String(safeHeaderValue(xfProto)),
      [H_XFH]: String(safeHeaderValue(xfHost)),
      ...(xff ? { [H_XFF]: String(xff) } : {}),
      ...(remoteAddr ? { [H_XREAL]: String(remoteAddr) } : {}),
      [H_XFPORT]: String(externalPort),
    };

    if (wsForceLocalOrigin && isLoopbackHost(upstreamHost) && rebuilt.origin) {
      rebuilt.origin = `${xfProto}://${buildLocalHostHeader(upstreamHost, internalPort)}`;
    }

    return applyGatewayTokenToHeaders(rebuilt);
  }

  // Non-strip path: keep most headers, but still ensure Host is sensible.
  if (forWs && wsForceLocalHostHeader && isLoopbackHost(upstreamHost)) {
    cleaned.host = buildLocalHostHeader(upstreamHost, internalPort);
  } else {
    cleaned.host = pickHostHeaderForUpstream(req, xfHost);
  }

  if (selfSanitize) {
    const base = stripProxyDerivedHeaders(cleaned);
    base.host =
      String(cleaned.host || base.host || "").trim() || buildLocalHostHeader(upstreamHost, internalPort);

    const rebuilt = {
      ...base,
      [H_XFP]: String(safeHeaderValue(xfProto)),
      [H_XFH]: String(safeHeaderValue(xfHost)),
      ...(xff ? { [H_XFF]: String(xff) } : {}),
      ...(remoteAddr ? { [H_XREAL]: String(remoteAddr) } : {}),
      [H_XFPORT]: String(externalPort),
    };

    if (forWs && wsForceLocalOrigin && isLoopbackHost(upstreamHost) && rebuilt.origin) {
      rebuilt.origin = `${xfProto}://${buildLocalHostHeader(upstreamHost, internalPort)}`;
    }

    return applyGatewayTokenToHeaders(rebuilt);
  }

  const withForwarded = {
    ...cleaned,
    [H_XFP]: String(safeHeaderValue(xfProto)),
    [H_XFH]: String(safeHeaderValue(xfHost)),
    ...(xff ? { [H_XFF]: String(xff) } : {}),
    ...(remoteAddr ? { [H_XREAL]: String(remoteAddr) } : {}),
    [H_XFPORT]: String(externalPort),
  };

  if (forWs && wsForceLocalOrigin && isLoopbackHost(upstreamHost) && withForwarded.origin) {
    withForwarded.origin = `${xfProto}://${buildLocalHostHeader(upstreamHost, internalPort)}`;
  }

  return applyGatewayTokenToHeaders(withForwarded);
}

async function isOpenClawReadyFast() {
  if (clawReady) return true;
  const sig = await isOpenClawReadySignal();
  return sig.ok;
}

function serveJson(res, code, obj) {
  res.statusCode = code;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(obj, null, 2));
}

function serveText(res, code, text) {
  res.statusCode = code;
  res.setHeader("content-type", "text/plain");
  res.end(text);
}

/**
 * Filter hop-by-hop headers for normal HTTP proxying.
 * For WebSocket handshake responses we must keep Connection and Upgrade.
 */
function filterHopByHopResponseHeaders(headers, opts = {}) {
  const keepWsHandshake = !!opts.keepWsHandshake;
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const lk = String(k).toLowerCase();
    if (HOP_BY_HOP.has(lk)) {
      if (keepWsHandshake && (lk === "connection" || lk === "upgrade")) {
        out[k] = v;
        continue;
      }
      continue;
    }
    out[k] = v;
  }
  return out;
}

function requestUpstream(req, res) {
  const url = req.url || "/";
  const headers = buildForwardedHeaders(req, { forWs: false });

  const client = selectUpstreamClient();
  const agent = selectUpstreamAgent();

  const options = {
    agent,
    hostname: upstreamHost,
    port: internalPort,
    method: req.method,
    path: url,
    headers,
    timeout: proxyTimeoutMs,
  };

  if (upstreamProtocol === "https") {
    options.rejectUnauthorized = !upstreamInsecure;
  }

  const proxyReq = client.request(options, (proxyRes) => {
    // If upstream says 401/403 and we have a token but were not injecting because childUsesTokenAuth was false,
    // enable it for future requests.
    const sc = Number(proxyRes.statusCode || 0);
    if ((sc === 401 || sc === 403) && token && injectGatewayTokenHeaders && !childUsesTokenAuth) {
      childUsesTokenAuth = true;
      console.log("[railway-start] upstream returned 401/403, enabling childUsesTokenAuth for future requests");
    }

    const safeHeaders = filterHopByHopResponseHeaders(proxyRes.headers);
    res.writeHead(proxyRes.statusCode || 502, safeHeaders);

    proxyRes.on("error", () => {
      try {
        if (!res.headersSent) serveText(res, 502, "Bad gateway");
      } catch {}
      try {
        res.end();
      } catch {}
    });

    proxyRes.pipe(res);
  });

  proxyReq.on("socket", (s) => {
    try {
      s.setNoDelay(true);
      s.setKeepAlive(true);
    } catch {}
  });

  const abortUpstream = () => {
    try {
      proxyReq.destroy();
    } catch {}
  };
  req.on("aborted", abortUpstream);
  res.on("close", abortUpstream);

  proxyReq.on("timeout", () => {
    try {
      proxyReq.destroy(new Error("upstream timeout"));
    } catch {}
  });

  proxyReq.on("error", (err) => {
    console.log("[railway-start] Proxy error:", err?.message || err);
    if (!res.headersSent) {
      serveText(res, 502, `Bad gateway: ${err?.message || err}. Check /debug.`);
    } else {
      try {
        res.end();
      } catch {}
    }
  });

  req.pipe(proxyReq);
}

// -----------------
// Adaptive flag fallback support
// -----------------
function detectUnknownFlagLine(line) {
  const low = String(line || "").toLowerCase();
  if (!low) return null;

  const looksUnknown =
    low.includes("unknown option") ||
    low.includes("unknown argument") ||
    low.includes("unrecognized option") ||
    low.includes("unknown flag") ||
    low.includes("invalid option");

  if (!looksUnknown) return null;

  if (low.includes("--no-doctor")) return "--no-doctor";
  if (low.includes("--allow-unconfigured")) return "--allow-unconfigured";
  return "__unknown__";
}

function maybeDisableFlagFromUnknown(flag) {
  if (disableFlagAutofallback) return false;

  if (flag === "--no-doctor" && flagNoDoctor) {
    flagNoDoctor = false;
    console.log("[railway-start] disabling --no-doctor due to unknown option from OpenClaw");
    return true;
  }

  if (flag === "--allow-unconfigured" && flagAllowUnconfigured) {
    flagAllowUnconfigured = false;
    console.log("[railway-start] disabling --allow-unconfigured due to unknown option from OpenClaw");
    return true;
  }

  return false;
}

// -----------------
// OpenClaw start loop
// -----------------
async function startOpenClawLoop() {
  const myLoopId = ++startLoopId;

  if (clawStarting) {
    console.log("[railway-start] OpenClaw start already in progress, skipping");
    return;
  }

  if (claw) {
    console.log("[railway-start] OpenClaw already running, skipping");
    return;
  }

  clawStarting = true;
  clawReady = false;

  outRing.length = 0;
  errRing.length = 0;

  const bindMode = currentBindForAttempt(restartAttempt);
  console.log("[railway-start] starting attempt", restartAttempt + 1, "bind =", bindMode);

  try {
    claw = spawnOpenClawProcess(bindMode);
    console.log("[railway-start] OpenClaw spawned PID:", claw.pid);
  } catch (e) {
    console.error("[railway-start] Failed to spawn OpenClaw:", e?.message || e);
    claw = null;
    clawStarting = false;

    restartAttempt += 1;
    const waitMs = computeBackoffMs(restartAttempt);
    console.log("[railway-start] spawn failed, retrying in", waitMs, "ms");
    await sleep(waitMs);

    if (myLoopId === startLoopId) startOpenClawLoop();
    return;
  }

  let triggeredUnknownFlagRestart = false;

  const handleUnknownFlagMaybe = (ln) => {
    const unknownFlag = detectUnknownFlagLine(ln);
    if (!triggeredUnknownFlagRestart && unknownFlag && unknownFlag !== "__unknown__") {
      const changed = maybeDisableFlagFromUnknown(unknownFlag);
      if (changed) {
        triggeredUnknownFlagRestart = true;
        console.log("[railway-start] restarting to retry without unsupported flag:", unknownFlag);

        const child = claw;
        claw = null;
        clawReady = false;
        clawStarting = false;
        startLoopId++;
        killChild(child);

        restartAttempt = Math.max(1, restartAttempt);
        scheduleRestart(800);
        return true;
      }
    }
    return false;
  };

  const noteChildUsesToken = (why) => {
    if (!token) return;
    if (!injectGatewayTokenHeaders) return;
    if (!childUsesTokenAuth) {
      childUsesTokenAuth = true;
      console.log("[railway-start] enabling childUsesTokenAuth due to:", why);
    }
  };

  if (claw.stdout) {
    claw.stdout.on("data", (data) => {
      const lines = data
        .toString()
        .split("\n")
        .map((x) => x.trimEnd())
        .filter(Boolean);
      for (const ln of lines) {
        pushRing(outRing, ln);
        console.log("[openclaw]", ln);

        if (handleUnknownFlagMaybe(ln)) return;

        // If OpenClaw logs imply token mode, ensure we inject token on proxy and readiness.
        const low = String(ln || "").toLowerCase();
        if (low.includes("auth") && low.includes("token")) noteChildUsesToken("stdout indicates token auth");

        if (token && !injectGatewayTokenHeaders) {
          if (low.includes("token_mismatch") || low.includes("token mismatch")) {
            injectGatewayTokenHeaders = true;
            console.log("[railway-start] detected token mismatch log; enabling injectGatewayTokenHeaders");
          }
        }
      }
    });
    claw.stdout.on("end", () => console.log("[railway-start] child stdout ended"));
  }

  if (claw.stderr) {
    claw.stderr.on("data", (data) => {
      const lines = data
        .toString()
        .split("\n")
        .map((x) => x.trimEnd())
        .filter(Boolean);

      for (const ln of lines) {
        pushRing(errRing, ln);
        console.error("[openclaw ERROR]", ln);

        if (handleUnknownFlagMaybe(ln)) return;

        const low = String(ln || "").toLowerCase();

        if (autoPassTokenOnAuthError && !passGatewayTokenToChild && token) {
          const hit =
            low.includes("gateway auth is set to token") &&
            (low.includes("no token is configured") || low.includes("set gateway.auth.token"));

          if (hit) {
            passGatewayTokenToChild = true;
            noteChildUsesToken("stderr auth missing suggests token mode");
            console.log(
              "[railway-start] detected auth token missing; enabling passGatewayTokenToChild for next restart"
            );
          }
        }

        // If OpenClaw is in token mode (or complains about tokens), inject in proxy path.
        if (low.includes("token")) {
          if (low.includes("token_mismatch") || low.includes("token mismatch")) {
            if (token && !injectGatewayTokenHeaders) {
              injectGatewayTokenHeaders = true;
              console.log("[railway-start] detected token mismatch; enabling injectGatewayTokenHeaders");
            }
            noteChildUsesToken("token mismatch log");
          } else if (low.includes("auth") && low.includes("token")) {
            noteChildUsesToken("stderr indicates token auth");
          }
        }
      }
    });
    claw.stderr.on("end", () => console.log("[railway-start] child stderr ended"));
  }

  claw.on("exit", (code, signal) => {
    console.log("[railway-start] OpenClaw exited code:", code, "signal:", signal);

    dumpRing("[railway-start][openclaw STDOUT]", outRing);
    dumpRing("[railway-start][openclaw STDERR]", errRing);

    if (myLoopId !== startLoopId) {
      console.log("[railway-start] superseded by newer start attempt, not restarting");
      return;
    }

    claw = null;
    clawStarting = false;
    clawReady = false;

    restartAttempt += 1;
    const waitMs = computeBackoffMs(restartAttempt);
    scheduleRestart(waitMs);
  });

  claw.on("error", (err) => {
    console.error("[railway-start] OpenClaw process error:", err?.message || err);

    dumpRing("[railway-start][openclaw STDOUT]", outRing);
    dumpRing("[railway-start][openclaw STDERR]", errRing);

    if (myLoopId !== startLoopId) {
      console.log("[railway-start] superseded, not restarting");
      return;
    }

    const child = claw;
    claw = null;
    clawStarting = false;
    clawReady = false;

    try {
      if (child) killChild(child);
    } catch {}

    restartAttempt += 1;
    const waitMs = computeBackoffMs(restartAttempt);
    scheduleRestart(waitMs);
  });

  const becameReady = await waitForOpenClawReady(startupTimeoutMs, claw);

  if (myLoopId !== startLoopId) {
    clawStarting = false;
    return;
  }

  if (!becameReady) {
    console.error("[railway-start] OpenClaw did not become ready in time, restarting");
    dumpRing("[railway-start][openclaw STDOUT]", outRing);
    dumpRing("[railway-start][openclaw STDERR]", errRing);

    startLoopId++;

    const child = claw;
    claw = null;
    clawReady = false;
    clawStarting = false;
    killChild(child);

    restartAttempt += 1;
    const waitMs = computeBackoffMs(restartAttempt);
    scheduleRestart(waitMs);
    return;
  }

  restartAttempt = 0;
  clawStarting = false;
  clawReady = true;
  console.log("[railway-start] OpenClaw is ready");
}

function safeEndThenDestroy(socketLike) {
  if (!socketLike) return;

  try {
    if (socketLike.writable && !socketLike.destroyed) socketLike.end();
  } catch {}

  const t = setTimeout(() => {
    try {
      if (!socketLike.destroyed) socketLike.destroy();
    } catch {}
  }, wsCloseDelayMs);

  try {
    t.unref();
  } catch {}
}

// If OpenClaw binds to externalPort, do not start wrapper server (port collision).
if (openclawListenOnExternal) {
  console.log("[railway-start] OPENCLAW_LISTEN_ON_EXTERNAL=1");
  console.log("[railway-start] wrapper HTTP server disabled to avoid EADDRINUSE");
  console.log("[railway-start] OpenClaw should serve /health /ready or its own endpoints");
  console.log("[railway-start] bind mode forced to lan in this mode");

  setTimeout(() => startOpenClawLoop(), 0);

  if (externalWatchdogEnabled) {
    setInterval(async () => {
      if (!claw || clawStarting) return;
      const ok = await isOpenClawReadyFast();
      if (ok) return;

      console.error("[railway-start] watchdog: OpenClaw not ready, restarting");
      dumpRing("[railway-start][openclaw STDOUT]", outRing);
      dumpRing("[railway-start][openclaw STDERR]", errRing);

      const child = claw;
      claw = null;
      clawReady = false;
      killChild(child);

      restartAttempt = Math.max(1, restartAttempt);
      scheduleRestart(computeBackoffMs(1));
    }, watchdogIntervalMs).unref();
  } else {
    console.log("[railway-start] external mode watchdog disabled (set OPENCLAW_EXTERNAL_WATCHDOG=1 to enable)");
  }

  function shutdown(reason) {
    console.log("[railway-start] shutdown:", reason);
    const child = claw;
    claw = null;
    if (child) killChild(child);
    setTimeout(() => process.exit(0), 3500);
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("uncaughtException", (e) => {
    console.error("[railway-start] uncaughtException:", e?.stack || e);
    shutdown("uncaughtException");
  });
  process.on("unhandledRejection", (e) => {
    console.error("[railway-start] unhandledRejection:", e?.stack || e);
    shutdown("unhandledRejection");
  });
} else {
  const server = http.createServer(async (req, res) => {
    const url = req.url || "/";

    if (
      enforceProxyToken &&
      url !== "/health" &&
      url !== "/ready" &&
      url !== "/debug" &&
      !isPublicUiPath(url)
    ) {
      const check = checkProxyToken(req);
      if (!check.ok) return serveText(res, 401, "unauthorized");
    }

    if (url === "/health") return serveText(res, 200, "ok");

    if (url === "/ready") {
      const ok = await isOpenClawReadyFast();
      return serveText(res, ok ? 200 : 503, ok ? "ready" : "not-ready");
    }

    if (url === "/debug") {
      const sig = await isOpenClawReadySignal();
      const tfp = tokenFingerprint(token);

      return serveJson(res, 200, {
        externalPort,
        internalPort,
        proxyEnabled,
        openclawListenOnExternal,
        upstreamProtocol,
        upstreamHost,
        upstreamHostHeaderOverride,
        upstreamForceLocalHostHeader,

        clawReady,
        clawRunning: !!claw,
        clawPid: claw?.pid || null,

        readyMode: readyCheckMode,
        readyPath,
        readyFallbackPaths,
        readyExpect: readyExpectRaw,
        readyOk: sig.ok,
        readyDetail: sig.detail,

        stateDir,
        mirrorDirs,

        enforceTokenAuth,
        injectGatewayTokenHeaders,
        passGatewayTokenToChild,
        childUsesTokenAuth,

        tokenHeaderCompat,
        legacyGatewayTokenHeader,

        autoPassTokenOnAuthError,

        enforceProxyToken,
        selfSanitize,

        tokenFingerprint: tfp,

        startupTimeoutMs,
        watchdogIntervalMs,
        proxyTimeoutMs,

        restartAttempt,
        restartScheduled,
        clawStarting,

        bindPrimary,
        bindFallback,

        OPENCLAW_SHELL_LOCAL_BIN: useShellForLocalBin,
        OPENCLAW_FORCE: forceRequested,
        OPENCLAW_FORCE_ENABLED: forceEnabled,

        flagAllowUnconfigured,
        flagNoDoctor,
        disableFlagAutofallback,

        wsCloseDelayMs,
        wsStripProxyHeaders,
        wsForceLocalHostHeader,
        wsForceLocalOrigin,

        trustedProxies: trusted,
        outTail: outRing.slice(-120),
        errTail: errRing.slice(-120),
      });
    }

    if (!claw && !clawStarting) {
      setTimeout(() => startOpenClawLoop(), 0);
    }

    if (!proxyEnabled) {
      return serveText(res, 404, "Proxy disabled. Use /health /ready /debug.");
    }

    const isReady = await isOpenClawReadyFast();
    if (!isReady) return serveText(res, 503, "OpenClaw is not ready yet. Check /debug.");

    requestUpstream(req, res);
  });

  server.requestTimeout = 0;
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;

  server.on("connection", (sock) => {
    try {
      sock.setNoDelay(true);
      sock.setKeepAlive(true);
    } catch {}
  });

  server.on("error", (e) => {
    console.error("[railway-start] server error:", e?.stack || e);
  });

  server.on("clientError", (err, socket) => {
    try {
      if (socket && socket.writable) {
        socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      }
    } catch {}
    try {
      socket.destroy();
    } catch {}
  });

  // WebSocket upgrade proxy
  server.on("upgrade", async (req, socket, head) => {
    let upstreamReq = null;
    let upstreamSocket = null;
    let upgraded = false;
    let closing = false;

    try {
      socket.pause();
    } catch {}

    try {
      socket.setNoDelay(true);
      socket.setTimeout(0);
      socket.setKeepAlive(true);
    } catch {}

    const destroyBoth = (why = "") => {
      if (closing) return;
      closing = true;
      if (why) console.log("[railway-start] ws closing:", why);

      try {
        if (upstreamReq) upstreamReq.destroy();
      } catch {}

      try {
        if (upstreamSocket) safeEndThenDestroy(upstreamSocket);
      } catch {}
      try {
        if (socket) safeEndThenDestroy(socket);
      } catch {}
    };

    try {
      const url = req.url || "/";

      if (enforceProxyToken && url !== "/debug" && !isPublicUiPath(url)) {
        const check = checkProxyToken(req);
        if (!check.ok) return destroyBoth("proxy token rejected");
      }

      if (!proxyEnabled) return destroyBoth("proxy disabled");

      const isReady = await isOpenClawReadyFast();
      if (!isReady) return destroyBoth("upstream not ready");

      const headers = buildForwardedHeaders(req, { forWs: true });

      const client = selectUpstreamClient();

      const options = {
        agent: false,
        hostname: upstreamHost,
        port: internalPort,
        method: req.method,
        path: url,
        headers: {
          ...headers,
          connection: "Upgrade",
          upgrade: "websocket",
        },
        timeout: proxyTimeoutMs,
      };

      if (upstreamProtocol === "https") {
        options.rejectUnauthorized = !upstreamInsecure;
      }

      upstreamReq = client.request(options);

      upstreamReq.on("socket", (s) => {
        try {
          s.setNoDelay(true);
          s.setTimeout(0);
          s.setKeepAlive(true);
        } catch {}
      });

      socket.on("timeout", () => destroyBoth("client socket timeout"));
      socket.on("error", () => destroyBoth("client socket error"));
      socket.on("end", () => destroyBoth("client socket ended"));
      socket.on("close", () => {
        if (!upgraded) destroyBoth("client socket closed before upgrade complete");
      });

      upstreamReq.on("response", (upstreamRes) => {
        try {
          const statusCode = upstreamRes.statusCode || 502;
          const statusMsg = upstreamRes.statusMessage || "";
          const safeHeaders = filterHopByHopResponseHeaders(upstreamRes.headers);
          const lines = [
            `HTTP/${upstreamRes.httpVersion || "1.1"} ${statusCode} ${statusMsg}`.trim(),
            ...headersToLines(safeHeaders),
            "",
            "",
          ];
          socket.write(lines.join("\r\n"));

          upstreamRes.on("data", (chunk) => {
            try {
              socket.write(chunk);
            } catch {}
          });

          upstreamRes.on("end", () => {
            try {
              socket.end();
            } catch {}
            destroyBoth("upstream ended non-upgrade response");
          });

          upstreamRes.on("error", () => destroyBoth("upstream response error"));

          try {
            socket.resume();
          } catch {}
        } catch {
          destroyBoth("response handler threw");
        }
      });

      upstreamReq.on("upgrade", (upstreamRes, us, uHead) => {
        upstreamSocket = us;
        upgraded = true;

        try {
          socket.setNoDelay(true);
          socket.setTimeout(0);
          socket.setKeepAlive(true);
        } catch {}
        try {
          upstreamSocket.setNoDelay(true);
          upstreamSocket.setTimeout(0);
          upstreamSocket.setKeepAlive(true);
        } catch {}

        // IMPORTANT: keep Connection and Upgrade on WS handshake response
        const safeHeaders = filterHopByHopResponseHeaders(upstreamRes.headers, { keepWsHandshake: true });
        // Force required headers in case upstream response omits them
        safeHeaders.connection = safeHeaders.connection || "Upgrade";
        safeHeaders.upgrade = safeHeaders.upgrade || "websocket";

        const lines = [
          `HTTP/${upstreamRes.httpVersion || "1.1"} ${upstreamRes.statusCode} ${
            upstreamRes.statusMessage || ""
          }`.trim(),
          ...headersToLines(safeHeaders),
          "",
          "",
        ];
        socket.write(lines.join("\r\n"));

        if (head && head.length) {
          try {
            upstreamSocket.write(head);
          } catch {}
        }

        if (uHead && uHead.length) {
          try {
            socket.write(uHead);
          } catch {}
        }

        upstreamSocket.on("timeout", () => destroyBoth("upstream socket timeout"));
        upstreamSocket.on("error", () => destroyBoth("upstream socket error"));
        upstreamSocket.on("end", () => destroyBoth("upstream socket ended"));
        upstreamSocket.on("close", () => destroyBoth("upstream socket closed"));

        try {
          socket.resume();
        } catch {}

        // Pipe both ways (same behavior, just not chained for easier debugging)
        socket.pipe(upstreamSocket);
        upstreamSocket.pipe(socket);
      });

      upstreamReq.on("timeout", () => destroyBoth("upstream request timeout"));
      upstreamReq.on("error", (e) => destroyBoth(`upstream request error: ${e?.message || e}`));

      upstreamReq.end();
    } catch (e) {
      destroyBoth(`upgrade handler exception: ${e?.message || e}`);
    }
  });

  server.listen(externalPort, "0.0.0.0", () => {
    console.log("[railway-start] public server listening on 0.0.0.0:" + externalPort);
    console.log("[railway-start] endpoints: /health /ready /debug");
    console.log("[railway-start] proxyEnabled =", proxyEnabled ? "yes" : "no");
    if (proxyEnabled) {
      console.log(
        "[railway-start] proxying other routes to",
        `${upstreamProtocol}://${upstreamHost}:${internalPort}`
      );
    }

    setTimeout(() => startOpenClawLoop(), 400);

    setInterval(async () => {
      if (!claw || clawStarting) return;
      const ok = await isOpenClawReadyFast();
      if (ok) return;

      console.error("[railway-start] watchdog: OpenClaw not ready, restarting");
      dumpRing("[railway-start][openclaw STDOUT]", outRing);
      dumpRing("[railway-start][openclaw STDERR]", errRing);

      const child = claw;
      claw = null;
      clawReady = false;
      killChild(child);

      restartAttempt = Math.max(1, restartAttempt);
      scheduleRestart(computeBackoffMs(1));
    }, watchdogIntervalMs).unref();
  });

  function shutdown(reason) {
    console.log("[railway-start] shutdown:", reason);
    try {
      server.close();
    } catch {}
    const child = claw;
    claw = null;
    if (child) killChild(child);
    setTimeout(() => process.exit(0), 3500);
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("uncaughtException", (e) => {
    console.error("[railway-start] uncaughtException:", e?.stack || e);
    shutdown("uncaughtException");
  });
  process.on("unhandledRejection", (e) => {
    console.error("[railway-start] unhandledRejection:", e?.stack || e);
    shutdown("unhandledRejection");
  });
}
