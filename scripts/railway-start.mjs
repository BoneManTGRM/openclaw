// scripts/railway-start.mjs
// Railway friendly OpenClaw launcher and proxy.
//
// What this file does
// - Starts OpenClaw gateway on an internal port (default 8081) and proxies Railway PORT to it.
// - Optionally lets OpenClaw bind directly to Railway PORT when OPENCLAW_LISTEN_ON_EXTERNAL=1.
// - Writes a safe OpenClaw config (openclaw.json + config.json) with gateway.port and gateway.trustedProxies.
// - Prevents pairing-required loops on Railway by sanitizing proxy-derived headers when selfSanitize is enabled.
// - Fixes loopback Host header mismatch that can flip OpenClaw into "remote" mode.
// - Optionally writes auth-profiles.json from env vars or ANTHROPIC_API_KEY / OPENAI_API_KEY.
//
// Key improvements in this revision
// - Secure /debug by default when OPENCLAW_GATEWAY_TOKEN exists (toggle OPENCLAW_DEBUG_PUBLIC=1 to allow public).
// - WS auth check runs before URL token param rewrite (future-proof if you ever allow query-param proxy auth).
// - removeClientAuthHeaders drops only lowercase header keys (Node incoming headers are lowercase).
// - rewriteUrlTokenParams is now gated behind OPENCLAW_REWRITE_QUERY_TOKENS=1 (default off).
//
// IMPORTANT FIX ADDED HERE (most common Railway issue):
// - OpenClaw sometimes ignores OPENCLAW_STATE_DIR and reads config only from $HOME/.openclaw (or /home/node/.openclaw).
// - This script mirrors config and auth-profiles into BOTH the chosen writable stateDir AND any writable "standard" dirs.
//
// Additional fixes in this update
// - Mirror dirs now include /root/.openclaw (some Railway images run as root).
// - Hop-by-hop header set corrected to include "trailer" (not "trailers") and "proxy-connection".
// - Response hop-by-hop filter matches the corrected set.
//
// WS TOKEN FIX
// - OpenClaw WS auth may read token from Sec-WebSocket-Protocol (subprotocol) and/or URL query (?token=...)
// - This proxy can inject the server token into both channels for upstream WS handshakes when childUsesTokenAuth.
// - SAFARI NOTE: Many iOS Safari builds are picky about custom subprotocols. Use OPENCLAW_WS_TOKEN_PROTOCOL_MODE=off.
//
// New knobs
// - OPENCLAW_WS_TOKEN_PROTOCOL_MODE = off | single | multi
//   off: do not modify Sec-WebSocket-Protocol (recommended for iOS Safari)
//   single: inject one token subprotocol
//   multi: inject several token subprotocol variants (maximum compatibility, can break picky clients)
// - OPENCLAW_WS_FORCE_LOCAL_ORIGIN defaults to true now (safer for loopback upstream on Railway)
// - OPENCLAW_REWRITE_QUERY_TOKENS = 0|1 (default 0)
//   If enabled, the proxy will rewrite token-like query parameters in the upstream URL to the server token.
//   Default is off to avoid breaking UI asset URLs that may contain query params.
//
// Fixes added in this update (for empty assistant replies debugging)
// - Always rewrite Origin on WS when upstream is loopback and wsForceLocalOrigin is enabled.
// - Add /openclaw-log endpoint to tail the OpenClaw log file from inside the container (secured like /debug).
// - Log a safe fingerprint for ANTHROPIC_API_KEY presence (no secret printed).
//
// IMPORTANT CONFIG FIX (channels disappearing):
// - Previous "selfSanitize" behavior overwrote config with a minimal object and dropped keys like channels.
// - Now, OPENCLAW_SELF_SANITIZE=1 means "patch in place" (preserve existing keys like channels).
// - If you truly want the old strict minimal overwrite, set OPENCLAW_SELF_SANITIZE_STRICT=1.
//
// IMPORTANT CHANGE IN THIS UPDATE (requested):
// - selfSanitize default is now OFF.
// - Enable by setting OPENCLAW_SELF_SANITIZE=1.
// - It can be disabled explicitly via OPENCLAW_SELF_SANITIZE=0/false/off/no
// - Also supports alternate disable env vars:
//   OPENCLAW_DISABLE_SELF_SANITIZE=1, OPENCLAW_NO_SELF_SANITIZE=1, DISABLE_SELF_SANITIZE=1, NO_SELF_SANITIZE=1
//
// NEW FIX (workspace dir safety):
// - If OPENCLAW_WORKSPACE_DIR is set but not writable (common on Railway when /data is not actually writable),
//   this script auto-falls back to a writable workspace under stateDir and passes that to the child.
// - This lets you keep OPENCLAW_WORKSPACE_DIR set without breaking the runtime.
//
// NEW FIX (Railway healthcheck resilience):
// - Some Railway configs probe "/" by default.
// - "/" is the UI route and may return 401/403/404 depending on upstream state and auth.
// - This script can return 200 "ok" for "/" only when the request looks like a health probe,
//   while still proxying "/" for real browsers.
// - Toggle with OPENCLAW_ROOT_HEALTH_OK=0 to disable.
//
// NEW FIX (your request about OpenAI env vars):
// - By default, this script strips OPENAI_* env vars from the OpenClaw child process to avoid interference.
// - Set OPENCLAW_PASS_OPENAI_ENV=1 (or OPENCLAW_STRIP_OPENAI_ENV=0) to pass them through.
// - Auto generating the OpenAI profile in auth-profiles.json is now opt-in via OPENCLAW_ENABLE_OPENAI_PROFILE=1.
//
// NEW FIX (Channels UI on token enforced proxy):
// - If OPENCLAW_PROXY_ENFORCE_TOKEN=1, the wrapper must not block the Control UI API routes,
//   otherwise the UI shows "Channel config schema unavailable".
// - This update treats common UI API prefixes as "public UI paths" for the purpose of proxy token enforcement.
//
// IMPORTANT FIXES APPLIED IN THIS UPDATE (per your screenshots and the review):
// - Default OPENCLAW_PROXY_TIMEOUT_MS is now 0 (no timeout). This avoids killing long lived streams.
// - WebSocket upstream request does not set an HTTP timeout at all.
// - /openclaw-log tail is capped by bytes to avoid reading huge files.
// - Expanded isPublicUiPath allowlist for Channels/Instances/Sessions schema routes.
// - Added safe logging when proxy token enforcement blocks a request so you can see what path was blocked.
//
// Small additions in this update
// - If OPENCLAW_PROXY_ENFORCE_TOKEN=1 but OPENCLAW_GATEWAY_TOKEN is empty, automatically disable enforcement to avoid lockout.
// - HEAD requests to /health, /ready, /debug, /openclaw-log return headers only (useful for some probes).

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

function envTruthy(name) {
  const v = String(process.env[name] || "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

function envFalsy(name) {
  const v = String(process.env[name] || "").trim().toLowerCase();
  return v === "0" || v === "false" || v === "no" || v === "off";
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

// Redact token from logged exec lines only
function redactTokenArgsForLog(args) {
  const out = [];
  const a = Array.isArray(args) ? args : [];
  for (let i = 0; i < a.length; i++) {
    const cur = String(a[i] ?? "");
    out.push(cur);
    if (cur === "--token" && i + 1 < a.length) {
      out.push("<redacted>");
      i++;
    }
  }
  return out;
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

// Query token rewrite (default OFF)
const rewriteQueryTokens =
  envBool("OPENCLAW_REWRITE_QUERY_TOKENS", false) || envBool("OPENCLAW_REWRITE_TOKEN_PARAMS", false);

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
let childUsesTokenAuth = !!(enforceTokenAuth || passGatewayTokenToChild);

// OpenAI env stripping (default ON, per your request)
const passOpenaiEnv = envBool("OPENCLAW_PASS_OPENAI_ENV", false);
const stripOpenaiEnv = envBool("OPENCLAW_STRIP_OPENAI_ENV", !passOpenaiEnv);

// OpenAI profile generation (default OFF, opt-in)
const enableOpenaiProfile = envBool("OPENCLAW_ENABLE_OPENAI_PROFILE", false);

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

// Self sanitize config behavior
const selfSanitizeStrict = envBool("OPENCLAW_SELF_SANITIZE_STRICT", false);

const selfSanitizeDisabledByAny =
  envTruthy("OPENCLAW_DISABLE_SELF_SANITIZE") ||
  envTruthy("OPENCLAW_NO_SELF_SANITIZE") ||
  envTruthy("DISABLE_SELF_SANITIZE") ||
  envTruthy("NO_SELF_SANITIZE") ||
  envFalsy("OPENCLAW_SELF_SANITIZE");

const selfSanitizeRequested = envBool("OPENCLAW_SELF_SANITIZE", false);
const selfSanitize = selfSanitizeRequested && !selfSanitizeDisabledByAny;

let startupTimeoutMs = envInt("OPENCLAW_STARTUP_TIMEOUT_MS", 120000);
startupTimeoutMs = clamp(startupTimeoutMs, 15000, 600000);

const watchdogIntervalMs = envInt("OPENCLAW_WATCHDOG_INTERVAL_MS", 8000);

// IMPORTANT: default is now 0 (no timeout). If you set a positive value, HTTP proxy requests use it.
// WebSocket upstream does not set an HTTP timeout at all.
let proxyTimeoutMs = envInt("OPENCLAW_PROXY_TIMEOUT_MS", 0);
proxyTimeoutMs = Math.max(0, Number(proxyTimeoutMs) || 0);

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

// WS: force upstream Host to local loopback (default ON)
const wsForceLocalHostHeader = envBool("OPENCLAW_WS_FORCE_LOCAL_HOST", true);

// Optional: rewrite Origin to local when upstream is loopback
const wsForceLocalOrigin = envBool("OPENCLAW_WS_FORCE_LOCAL_ORIGIN", true);

// WS token protocol injection mode
function normalizeWsTokenProtocolMode(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (s === "off" || s === "none" || s === "0" || s === "false") return "off";
  if (s === "single" || s === "one") return "single";
  if (s === "multi" || s === "many") return "multi";
  return "off";
}
const wsTokenProtocolMode = normalizeWsTokenProtocolMode(
  envStr("OPENCLAW_WS_TOKEN_PROTOCOL_MODE", "off")
);

// OpenClaw expects bind MODEs here, not IPs.
const bindPrimaryEnv = envStr("OPENCLAW_BIND", "loopback");
const bindFallbackEnv = envStr("OPENCLAW_BIND_FALLBACK", "lan");

// If OpenClaw is the public listener, it cannot bind loopback on Railway
const bindPrimary = openclawListenOnExternal ? "lan" : bindPrimaryEnv;
const bindFallback = openclawListenOnExternal ? "lan" : bindFallbackEnv;

const useShellForLocalBin = envBool("OPENCLAW_SHELL_LOCAL_BIN", true);

// Optional: enforce a token on inbound requests to the wrapper proxy.
let enforceProxyToken = envBool("OPENCLAW_PROXY_ENFORCE_TOKEN", false);
if (enforceProxyToken && !token) {
  enforceProxyToken = false;
  console.log(
    "[railway-start] warning: OPENCLAW_PROXY_ENFORCE_TOKEN=1 but OPENCLAW_GATEWAY_TOKEN is empty"
  );
  console.log("[railway-start] warning: disabling enforceProxyToken to avoid lockout");
}

// /debug protection
const debugPublic = envBool("OPENCLAW_DEBUG_PUBLIC", false);
// If token exists and debugPublic is false, /debug requires token
const debugRequiresToken = envBool("OPENCLAW_DEBUG_REQUIRE_TOKEN", true);

// Proxy enabled by default, disabled automatically if OpenClaw is listening on external.
const proxyEnabled = envBool("OPENCLAW_PROXY_ENABLED", !openclawListenOnExternal);

// IMPORTANT: Fix "pairing required" on Railway Control UI
const controlUiAllowInsecureAuth = envBool(
  "OPENCLAW_CONTROL_UI_ALLOW_INSECURE_AUTH",
  proxyEnabled ? true : false
);

// Use --force only if explicitly requested AND lsof exists.
const forceRequested = envBool("OPENCLAW_FORCE", false);
const forceEnabled = forceRequested && hasWorkingLsof();

// Flags that may not exist on older builds
let flagAllowUnconfigured = envBool("OPENCLAW_ALLOW_UNCONFIGURED", true);
// Default false to avoid restart loops on builds that do not support it
let flagNoDoctor = envBool("OPENCLAW_NO_DOCTOR", false);

// Optional: enforce a strict retry without unknown flags by setting OPENCLAW_DISABLE_FLAG_AUTOFALLBACK=1
const disableFlagAutofallback = envBool("OPENCLAW_DISABLE_FLAG_AUTOFALLBACK", false);

// WS gentle close delay (helps iOS Safari)
let wsCloseDelayMs = envInt("OPENCLAW_WS_CLOSE_DELAY_MS", 120);
wsCloseDelayMs = clamp(wsCloseDelayMs, 0, 1500);

// Root healthcheck behavior for Railway
const rootHealthOk = envBool("OPENCLAW_ROOT_HEALTH_OK", true);

// Simplified stateDir selection
const candidates = [
  process.env.OPENCLAW_STATE_DIR,
  "/data/.openclaw",
  "/home/node/.openclaw",
  "/root/.openclaw",
  "/tmp/.openclaw",
].filter(Boolean);

let stateDir = "/tmp/.openclaw";
for (const dir of candidates) {
  if (canWriteDir(dir)) {
    stateDir = dir;
    break;
  }
}

safeMkdir(stateDir);

// Workspace dir safety
function resolveWorkspaceDir(primaryStateDir) {
  const requested = String(process.env.OPENCLAW_WORKSPACE_DIR || "").trim();
  if (requested) {
    if (canWriteDir(requested)) return { dir: requested, usedFallback: false, requested };
    const fallback = path.join(primaryStateDir, "workspace");
    safeMkdir(fallback);
    console.log("[railway-start] warning: OPENCLAW_WORKSPACE_DIR is not writable:", requested);
    console.log("[railway-start] using fallback workspaceDir:", fallback);
    return { dir: fallback, usedFallback: true, requested };
  }

  const fallback = path.join(primaryStateDir, "workspace");
  safeMkdir(fallback);
  return { dir: fallback, usedFallback: false, requested: "" };
}

const workspaceResolved = resolveWorkspaceDir(stateDir);
const workspaceDir = workspaceResolved.dir;

const tokenFp = tokenFingerprint(token);
const anthropicKeyFp = tokenFingerprint(envStr("ANTHROPIC_API_KEY", "").trim());

console.log("[railway-start] external PORT =", externalPort);
console.log("[railway-start] internal OpenClaw port =", internalPort);
console.log("[railway-start] proxyEnabled =", proxyEnabled ? "yes" : "no");
console.log("[railway-start] openclawListenOnExternal =", openclawListenOnExternal ? "yes" : "no");
console.log("[railway-start] chosen stateDir =", stateDir);
console.log("[railway-start] chosen workspaceDir =", workspaceDir);
if (workspaceResolved.requested) {
  console.log(
    "[railway-start] OPENCLAW_WORKSPACE_DIR requested =",
    workspaceResolved.requested,
    "effective =",
    workspaceDir,
    "fallbackUsed =",
    workspaceResolved.usedFallback ? "yes" : "no"
  );
}
console.log("[railway-start] token present =", token ? "yes" : "no");
console.log(
  "[railway-start] token fingerprint =",
  tokenFp.present ? `${tokenFp.sha256_8} (len ${tokenFp.len})` : "none"
);
console.log(
  "[railway-start] ANTHROPIC_API_KEY =",
  anthropicKeyFp.present ? `${anthropicKeyFp.sha256_8} (len ${anthropicKeyFp.len})` : "missing"
);
console.log("[railway-start] enforce gateway token auth =", enforceTokenAuth ? "yes" : "no");
console.log("[railway-start] inject gateway token headers =", injectGatewayTokenHeaders ? "yes" : "no");
console.log("[railway-start] pass gateway token to child =", passGatewayTokenToChild ? "yes" : "no");
console.log("[railway-start] childUsesTokenAuth =", childUsesTokenAuth ? "yes" : "no");
console.log("[railway-start] tokenHeaderCompat =", tokenHeaderCompat ? "yes" : "no");
console.log("[railway-start] legacyGatewayTokenHeader =", legacyGatewayTokenHeader ? "yes" : "no");
console.log("[railway-start] rewriteQueryTokens =", rewriteQueryTokens ? "yes" : "no");
console.log("[railway-start] stripOpenaiEnv =", stripOpenaiEnv ? "yes" : "no");
console.log("[railway-start] enableOpenaiProfile =", enableOpenaiProfile ? "yes" : "no");
if (passGatewayTokenToChild && !token) {
  console.log("[railway-start] warning: passGatewayTokenToChild=1 but token is empty");
}
console.log("[railway-start] autoPassTokenOnAuthError =", autoPassTokenOnAuthError ? "yes" : "no");
console.log("[railway-start] enforce proxy token =", enforceProxyToken ? "yes" : "no");
console.log("[railway-start] debugPublic =", debugPublic ? "yes" : "no");
console.log("[railway-start] debugRequiresToken =", debugRequiresToken ? "yes" : "no");
console.log("[railway-start] selfSanitize =", selfSanitize ? "yes" : "no");
console.log("[railway-start] selfSanitizeStrict =", selfSanitizeStrict ? "yes" : "no");
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
console.log("[railway-start] wsTokenProtocolMode =", wsTokenProtocolMode);
console.log("[railway-start] rootHealthOk =", rootHealthOk ? "yes" : "no");
console.log(
  "[railway-start] gateway.controlUi.allowInsecureAuth =",
  controlUiAllowInsecureAuth ? "yes" : "no"
);

if (openclawListenOnExternal) {
  console.log("[railway-start] warning: OPENCLAW_LISTEN_ON_EXTERNAL=1 disables wrapper server");
  console.log("[railway-start] recommended default on Railway is proxy mode (OPENCLAW_LISTEN_ON_EXTERNAL=0)");
  console.log("[railway-start] external watchdog enabled =", externalWatchdogEnabled ? "yes" : "no");
}

// Build a set of "standard" dirs OpenClaw may read from, and mirror config there if writable.
function computeMirrorDirs(primaryDir) {
  const out = [];

  const home = String(process.env.HOME || "").trim();
  if (home) out.push(path.join(home, ".openclaw"));

  out.push("/home/node/.openclaw");
  out.push("/root/.openclaw");
  out.push("/data/.openclaw");

  out.push(primaryDir);

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

function isPlainObject(x) {
  return !!x && typeof x === "object" && !Array.isArray(x);
}

function deepCloneJson(obj) {
  try {
    if (typeof globalThis.structuredClone === "function") return globalThis.structuredClone(obj);
  } catch {}
  try {
    return JSON.parse(JSON.stringify(obj ?? {}));
  } catch {
    return {};
  }
}

function deepMergePreferRight(left, right) {
  if (!isPlainObject(left)) return deepCloneJson(right);
  if (!isPlainObject(right)) return deepCloneJson(left);

  const out = deepCloneJson(left);

  for (const [k, rv] of Object.entries(right)) {
    const lv = out[k];

    if (isPlainObject(lv) && isPlainObject(rv)) {
      out[k] = deepMergePreferRight(lv, rv);
      continue;
    }

    if (Array.isArray(lv) && Array.isArray(rv)) {
      out[k] = rv.length ? rv.slice() : lv.slice();
      continue;
    }

    if (rv === undefined) {
      continue;
    }

    out[k] = deepCloneJson(rv);
  }

  return out;
}

function readFirstJsonFromPaths(paths) {
  const list = Array.isArray(paths) ? paths : [];
  for (const p of list) {
    const pp = String(p || "").trim();
    if (!pp) continue;
    const abs = path.isAbsolute(pp) ? pp : path.resolve(pp);
    const js = readJsonIfExists(abs);
    if (js) return { path: abs, json: js };
  }
  return { path: "", json: null };
}

// Read existing config (if any), but also allow seeding from a repo config file.
// This helps recover "channels" if the persisted config was previously minimized.
const repoConfigCandidates = uniq([
  envStr("OPENCLAW_REPO_CONFIG_PATH", "").trim(),
  "openclaw.json",
  "config/openclaw.json",
  ".openclaw/openclaw.json",
  "openclaw.config.json",
].filter(Boolean));

const repoSeed = readFirstJsonFromPaths(repoConfigCandidates);
if (repoSeed.json) {
  console.log("[railway-start] repo seed config found at", repoSeed.path);
} else {
  console.log("[railway-start] no repo seed config found (optional)");
}

const existingFromState =
  readJsonIfExists(path.join(stateDir, configAName)) ||
  readJsonIfExists(path.join(stateDir, configBName)) ||
  (mirrorDirs
    .map((d) => readJsonIfExists(path.join(d, configAName)) || readJsonIfExists(path.join(d, configBName)))
    .find(Boolean) ||
    {}) ||
  {};

const existing = repoSeed.json
  ? deepMergePreferRight(repoSeed.json, existingFromState)
  : existingFromState;

function getExistingGateway(base) {
  if (!isPlainObject(base)) return {};
  return isPlainObject(base.gateway) ? base.gateway : {};
}

const existingGateway = getExistingGateway(existing);

function dropLegacyBadKeys(cfg) {
  if (!isPlainObject(cfg)) return;

  delete cfg.trustProxy;
  delete cfg.trustedProxies;

  if (isPlainObject(cfg.gateway)) {
    delete cfg.gateway.trustProxy;
    delete cfg.gateway.trustProxies;
    delete cfg.gateway.pairingRequired;
  }
}

function buildPatchedConfigPreserveAll() {
  const base = isPlainObject(existing) ? deepCloneJson(existing) : {};
  base.gateway = isPlainObject(base.gateway) ? base.gateway : {};

  base.gateway.port = Number(internalPort);

  const trusted = uniq([
    ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
    ...parseTrustedProxies(),
  ]);
  base.gateway.trustedProxies = trusted;

  base.gateway.controlUi = isPlainObject(base.gateway.controlUi) ? base.gateway.controlUi : {};
  base.gateway.controlUi.allowInsecureAuth = !!controlUiAllowInsecureAuth;

  dropLegacyBadKeys(base);

  if (enforceTokenAuth && token) {
    base.gateway.auth = isPlainObject(base.gateway.auth) ? base.gateway.auth : {};
    base.gateway.auth.mode = "token";
    base.gateway.auth.token = token;
    console.log("[railway-start] gateway auth enabled (token)");
  } else {
    delete base.gateway.auth;
    console.log("[railway-start] gateway auth not configured");
  }

  return { cfg: base, trusted };
}

function buildStrictSanitizedConfigMinimal() {
  const cfg = {};
  cfg.gateway = {};

  cfg.gateway.port = Number(internalPort);

  const trusted = uniq([
    ...(Array.isArray(existingGateway.trustedProxies) ? existingGateway.trustedProxies : []),
    ...parseTrustedProxies(),
  ]);
  cfg.gateway.trustedProxies = trusted;

  cfg.gateway.controlUi = {
    allowInsecureAuth: !!controlUiAllowInsecureAuth,
  };

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
  const base = isPlainObject(existing) ? deepCloneJson(existing) : {};
  base.gateway = isPlainObject(base.gateway) ? base.gateway : {};

  base.gateway.port = Number(internalPort);

  const trusted = uniq([
    ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
    ...parseTrustedProxies(),
  ]);
  base.gateway.trustedProxies = trusted;

  base.gateway.controlUi = isPlainObject(base.gateway.controlUi) ? base.gateway.controlUi : {};
  base.gateway.controlUi.allowInsecureAuth = !!controlUiAllowInsecureAuth;

  dropLegacyBadKeys(base);

  if (enforceTokenAuth && token) {
    base.gateway.auth = isPlainObject(base.gateway.auth) ? base.gateway.auth : {};
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
  const built = selfSanitizeStrict ? buildStrictSanitizedConfigMinimal() : buildPatchedConfigPreserveAll();
  configToWrite = built.cfg;
  trusted = built.trusted;

  if (selfSanitizeStrict) {
    const existingRootKeys = Object.keys(isPlainObject(existing) ? existing : {});
    const keptRootKeys = ["gateway"];
    const droppedRoot = existingRootKeys.filter((k) => !keptRootKeys.includes(k));
    if (droppedRoot.length) {
      console.log("[railway-start] selfSanitizeStrict: dropped root keys:", droppedRoot.join(", "));
    }
    const existingGwKeys = Object.keys(existingGateway);
    const keptGwKeys = ["port", "trustedProxies", "controlUi", "auth"];
    const droppedGw = existingGwKeys.filter((k) => !keptGwKeys.includes(k));
    if (droppedGw.length) {
      console.log("[railway-start] selfSanitizeStrict: dropped gateway keys:", droppedGw.join(", "));
    }
  }
} else {
  const built = buildCompatConfig();
  configToWrite = built.cfg;
  trusted = built.trusted;
}

for (const d of mirrorDirs) {
  safeMkdir(d);
  safeWriteJson(path.join(d, configAName), configToWrite);
  safeWriteJson(path.join(d, configBName), configToWrite);
}

// Optional: write OpenClaw agent auth store if provided.
(function writeAuthProfilesIfProvided() {
  const jsonRaw = envStr("OPENCLAW_AUTH_PROFILES_JSON", "").trim();
  const b64 = envStr("OPENCLAW_AUTH_PROFILES_B64", "").trim();

  const openaiKey = enableOpenaiProfile ? envStr("OPENAI_API_KEY", "").trim() : "";
  const anthropicKey = envStr("ANTHROPIC_API_KEY", "").trim();

  if (!enableOpenaiProfile && envStr("OPENAI_API_KEY", "").trim()) {
    console.log("[railway-start] OPENAI_API_KEY present but OPENCLAW_ENABLE_OPENAI_PROFILE is not set, ignoring for auth-profiles");
  }

  if (!jsonRaw && !b64 && !openaiKey && !anthropicKey) {
    console.log(
      "[railway-start] no auth profiles env vars found (OPENCLAW_AUTH_PROFILES_JSON, OPENCLAW_AUTH_PROFILES_B64, ANTHROPIC_API_KEY, and OPENAI_API_KEY only if OPENCLAW_ENABLE_OPENAI_PROFILE=1)"
    );
    return;
  }

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

    const existingAuth = readJsonIfExists(authPath) || {};
    const next = isPlainObject(existingAuth) ? deepCloneJson(existingAuth) : {};

    next.profiles = isPlainObject(next.profiles) ? next.profiles : {};
    next.usageStats = isPlainObject(next.usageStats) ? next.usageStats : {};

    if (openaiKey) {
      next.profiles["openai:default"] = {
        type: "api_key",
        provider: "openai",
        key: openaiKey,
      };
    }

    if (anthropicKey) {
      next.profiles["anthropic:default"] = {
        type: "api_key",
        provider: "anthropic",
        key: anthropicKey,
      };
    }

    console.log("[railway-start] auto-generating auth-profiles.json (schema) to", authPath);
    safeWriteJson(authPath, next);

    try {
      const txt = fs.readFileSync(authPath, "utf8");
      const hasAnthropic =
        txt.includes('"provider": "anthropic"') || txt.includes('"provider":"anthropic"') || txt.includes("anthropic:default");
      const hasOpenai =
        txt.includes('"provider": "openai"') || txt.includes('"provider":"openai"') || txt.includes("openai:default");
      console.log("[railway-start] auth-profiles contains anthropic =", hasAnthropic ? "yes" : "no");
      console.log("[railway-start] auth-profiles contains openai =", hasOpenai ? "yes" : "no");
    } catch (e) {
      console.log("[railway-start] auth-profiles verification read failed:", e?.message || String(e));
    }
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
const MAX_LOG_BYTES = clamp(envInt("OPENCLAW_LOG_MAX_BYTES", 2000000), 200000, 20000000);

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
      console.log("[railway-start] warning: passGatewayTokenToChild=1 but token is empty, skipping --token");
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

  childEnv.OPENCLAW_STATE_DIR = stateDir;
  childEnv.OPENCLAW_CONFIG_DIR = stateDir;
  childEnv.OPENCLAW_HOME_DIR = stateDir;

  childEnv.OPENCLAW_WORKSPACE_DIR = workspaceDir;

  if (stripOpenaiEnv) {
    delete childEnv.OPENAI_API_KEY;
    delete childEnv.OPENAI_API_BASE;
    delete childEnv.OPENAI_BASE_URL;
    delete childEnv.OPENAI_ORGANIZATION;
    delete childEnv.OPENAI_PROJECT;
  }

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
  const argsForLog = redactTokenArgsForLog(args);

  childUsesTokenAuth = args.includes("--token") && !!token ? true : !!enforceTokenAuth;

  if (resolved.kind === "localbin" && useShellForLocalBin) {
    const cmdLine = shJoin(resolved.cmd, args);
    const cmdLineLog = shJoin(resolved.cmd, argsForLog);
    console.log("[railway-start] exec shell:", cmdLineLog);
    return spawn(cmdLine, { stdio: ["ignore", "pipe", "pipe"], env: childEnv, shell: true });
  }

  console.log("[railway-start] exec:", [resolved.cmd, ...argsForLog].join(" "));
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

  h["authorization"] = `Bearer ${token}`;
  h["x-clawdbot-token"] = token;

  if (tokenHeaderCompat) {
    h["x-openclaw-token"] = token;
  }
  if (legacyGatewayTokenHeader) {
    h["x-openclaw-gateway-token"] = token;
  }

  return h;
}

function applyGatewayTokenToHeadersForced(headers) {
  if (!token) return headers;
  const h = { ...(headers || {}) };
  h["authorization"] = `Bearer ${token}`;
  h["x-clawdbot-token"] = token;
  if (tokenHeaderCompat) h["x-openclaw-token"] = token;
  if (legacyGatewayTokenHeader) h["x-openclaw-gateway-token"] = token;
  return h;
}

// Removes any client-supplied auth headers to avoid stale-token loops
function removeClientAuthHeaders(headersObj) {
  const h = { ...(headersObj || {}) };
  delete h["authorization"];
  delete h["x-clawdbot-token"];
  delete h["x-openclaw-token"];
  delete h["x-openclaw-gateway-token"];
  delete h["x-api-key"];
  delete h["x-api_token"];
  delete h["x-api-token"];
  delete h["x-auth-token"];
  delete h["x-access-token"];
  delete h["apikey"];
  delete h["api-key"];
  return h;
}

// Token-like query keys sometimes used by clients
const TOKEN_QUERY_KEYS = new Set([
  "token",
  "auth",
  "authorization",
  "bearer",
  "access_token",
  "access-token",
  "api_key",
  "api-key",
  "apikey",
  "x-api-key",
  "x-auth-token",
  "x-access-token",
  "x-openclaw-token",
  "x-openclaw-gateway-token",
  "x-clawdbot-token",
  "openclaw_token",
  "claw_token",
  "clawdbot_token",
]);

function rewriteUrlTokenParams(urlRaw) {
  const raw = String(urlRaw || "/") || "/";
  if (!rewriteQueryTokens) return raw;
  if (!token) return raw;
  try {
    const u = new URL(raw, "http://local.invalid");
    let changed = false;
    for (const k of TOKEN_QUERY_KEYS) {
      if (u.searchParams.has(k)) {
        u.searchParams.set(k, token);
        changed = true;
      }
    }
    if (!changed) return raw;
    return `${u.pathname}${u.search}${u.hash}`;
  } catch {
    return raw;
  }
}

function safeHeaderValue(v) {
  const s = headerValueToString(v);
  return s.replace(/[\r\n]+/g, " ").trim();
}

// -----------------
// WS token injection helpers
// -----------------
function parseWsSubprotocols(raw) {
  const s = String(raw || "");
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function buildWsSubprotocolHeader(protocols) {
  return uniq(protocols).join(", ");
}

function stripTokenProtocolsFromList(protocols) {
  const list = Array.isArray(protocols) ? protocols : [];
  return list.filter((p) => {
    const lp = String(p || "").trim().toLowerCase();
    return (
      !lp.startsWith("openclaw-token.") &&
      !lp.startsWith("gateway-token.") &&
      !lp.startsWith("clawdbot-token.") &&
      !lp.startsWith("token.")
    );
  });
}

function stripTokenProtocolsFromHeaderValue(headerValue) {
  const current = headerValueToString(headerValue);
  const protocols = parseWsSubprotocols(current);
  const filtered = stripTokenProtocolsFromList(protocols);
  return filtered;
}

function injectGatewayTokenIntoWsHeaders(headersObj) {
  if (!token) return headersObj;
  if (!childUsesTokenAuth) return headersObj;

  const h = { ...(headersObj || {}) };

  const withHttpHeaders = applyGatewayTokenToHeaders(h);

  if (wsTokenProtocolMode === "off") {
    return withHttpHeaders;
  }

  const existing = withHttpHeaders["sec-websocket-protocol"] || "";
  const protocols = parseWsSubprotocols(existing);

  const filtered = stripTokenProtocolsFromList(protocols);

  if (wsTokenProtocolMode === "single") {
    filtered.push(`token.${token}`);
  } else if (wsTokenProtocolMode === "multi") {
    filtered.push(`token.${token}`);
    filtered.push(`openclaw-token.${token}`);
    filtered.push(`gateway-token.${token}`);
    filtered.push(`clawdbot-token.${token}`);
  } else {
    filtered.push(`token.${token}`);
  }

  withHttpHeaders["sec-websocket-protocol"] = buildWsSubprotocolHeader(filtered);
  return withHttpHeaders;
}

function sanitizeWsHandshakeResponseHeaders(headersObj) {
  const h = { ...(headersObj || {}) };
  const key = "sec-websocket-protocol";
  if (h[key] != null) {
    const filtered = stripTokenProtocolsFromHeaderValue(h[key]);
    if (!filtered.length) {
      delete h[key];
    } else {
      h[key] = buildWsSubprotocolHeader(filtered);
    }
  }
  return h;
}

function injectGatewayTokenIntoUpstreamWsPath(urlRaw) {
  if (!token) return String(urlRaw || "/") || "/";
  if (!childUsesTokenAuth) return String(urlRaw || "/") || "/";
  const raw = String(urlRaw || "/") || "/";
  try {
    const u = new URL(raw, "http://local.invalid");
    if (!u.searchParams.get("token")) u.searchParams.set("token", token);
    return `${u.pathname}${u.search}${u.hash}`;
  } catch {
    return raw;
  }
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

  const first = await httpReadyCheckOnce(readyPath);
  if (first.ok) {
    return {
      ok: true,
      detail: { ...r, http: true, path: first.path, code: first.code, expect: readyExpectRaw },
    };
  }

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

function checkDebugToken(req) {
  if (!debugRequiresToken) return { ok: true, reason: "debug-token-disabled" };
  if (!token) return { ok: true, reason: "no-server-token" };
  if (debugPublic) return { ok: true, reason: "debug-public" };

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

  // Control UI API routes (do not block these with proxy token enforcement)
  if (u.startsWith("/api/")) return true;
  if (u.startsWith("/trpc/")) return true;
  if (u.startsWith("/rpc/")) return true;

  // Control UI data routes seen in some builds
  if (u.startsWith("/channels")) return true;
  if (u.startsWith("/instances")) return true;
  if (u.startsWith("/sessions")) return true;
  if (u.startsWith("/schema")) return true;
  if (u.startsWith("/control")) return true;

  return false;
}

// Heuristic: treat "/" as 200 OK for health probes, but keep "/" proxied for browsers.
function isLikelyHealthProbe(req) {
  const method = String(req.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;

  const ua = String(req.headers["user-agent"] || "").toLowerCase();
  const accept = String(req.headers["accept"] || "").toLowerCase();

  if (ua.includes("railway")) return true;
  if (ua.includes("health")) return true;
  if (ua.includes("kube-probe")) return true;
  if (ua.includes("elb-healthchecker")) return true;
  if (ua.includes("googlehc")) return true;
  if (ua.includes("go-http-client")) return true;

  const looksHtml = accept.includes("text/html") || accept.includes("application/xhtml+xml");
  const looksBrowser =
    ua.includes("mozilla") || ua.includes("safari") || ua.includes("chrome") || ua.includes("iphone") || ua.includes("ipad");

  if (!looksHtml && !looksBrowser) return true;

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
  "proxy-connection",
  "te",
  "trailer",
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

    if (forWs && wsForceLocalOrigin && isLoopbackHost(upstreamHost)) {
      rebuilt.origin = `${upstreamProtocol}://${buildLocalHostHeader(upstreamHost, internalPort)}`;
    }

    const noClientAuth = removeClientAuthHeaders(rebuilt);

    if (forWs) {
      return injectGatewayTokenIntoWsHeaders(noClientAuth);
    }

    return applyGatewayTokenToHeaders(noClientAuth);
  }

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

    if (forWs && wsForceLocalOrigin && isLoopbackHost(upstreamHost)) {
      rebuilt.origin = `${upstreamProtocol}://${buildLocalHostHeader(upstreamHost, internalPort)}`;
    }

    const noClientAuth = removeClientAuthHeaders(rebuilt);

    if (forWs) {
      return injectGatewayTokenIntoWsHeaders(noClientAuth);
    }

    return applyGatewayTokenToHeaders(noClientAuth);
  }

  const withForwarded = {
    ...cleaned,
    [H_XFP]: String(safeHeaderValue(xfProto)),
    [H_XFH]: String(safeHeaderValue(xfHost)),
    ...(xff ? { [H_XFF]: String(xff) } : {}),
    ...(remoteAddr ? { [H_XREAL]: String(remoteAddr) } : {}),
    [H_XFPORT]: String(externalPort),
  };

  if (forWs && wsForceLocalOrigin && isLoopbackHost(upstreamHost)) {
    withForwarded.origin = `${upstreamProtocol}://${buildLocalHostHeader(upstreamHost, internalPort)}`;
  }

  const noClientAuth = removeClientAuthHeaders(withForwarded);

  if (forWs) {
    return injectGatewayTokenIntoWsHeaders(noClientAuth);
  }

  return applyGatewayTokenToHeaders(noClientAuth);
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

function serveTextHeadAware(req, res, code, text) {
  res.statusCode = code;
  res.setHeader("content-type", "text/plain");
  const m = String(req?.method || "GET").toUpperCase();
  if (m === "HEAD") return res.end();
  return res.end(text);
}

function serveJsonHeadAware(req, res, code, obj) {
  res.statusCode = code;
  res.setHeader("content-type", "application/json");
  const m = String(req?.method || "GET").toUpperCase();
  if (m === "HEAD") return res.end();
  return res.end(JSON.stringify(obj, null, 2));
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

// -----------------
// OpenClaw log tail helpers (/openclaw-log)
// -----------------
function safeReadDir(dir) {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

function safeStat(p) {
  try {
    return fs.statSync(p);
  } catch {
    return null;
  }
}

function findLatestOpenClawLog() {
  const dirs = uniq([
    "/tmp/openclaw",
    "/tmp",
    path.join(stateDir, "tmp", "openclaw"),
    path.join(stateDir, "openclaw"),
  ]);

  let best = { path: "", mtimeMs: 0 };

  for (const d of dirs) {
    const entries = safeReadDir(d);
    for (const name of entries) {
      if (!name || typeof name !== "string") continue;
      if (!name.startsWith("openclaw-") || !name.endsWith(".log")) continue;
      const p = path.join(d, name);
      const st = safeStat(p);
      if (!st || !st.isFile()) continue;
      const m = Number(st.mtimeMs || 0);
      if (m > best.mtimeMs) best = { path: p, mtimeMs: m };
    }
  }

  if (!best.path) {
    const fallback = "/tmp/openclaw/openclaw-" + new Date().toISOString().slice(0, 10) + ".log";
    if (fs.existsSync(fallback)) return fallback;
  }

  return best.path || "";
}

function readTailBytesSync(filePath, maxBytes) {
  const st = safeStat(filePath);
  if (!st || !st.isFile()) return null;

  const size = Number(st.size || 0);
  const cap = clamp(Number(maxBytes) || MAX_LOG_BYTES, 10000, MAX_LOG_BYTES);

  let start = 0;
  let len = size;

  if (size > cap) {
    start = size - cap;
    len = cap;
  }

  let fd = null;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, start);
    return buf.toString("utf8");
  } catch {
    return null;
  } finally {
    try {
      if (fd != null) fs.closeSync(fd);
    } catch {}
  }
}

function tailFile(filePath, lines = 600) {
  const p = String(filePath || "").trim();
  if (!p) return { ok: false, error: "no-log-found" };
  if (!fs.existsSync(p)) return { ok: false, error: "missing", path: p };

  const n = clamp(Number(lines) || 600, 10, 5000);

  try {
    const txt = readTailBytesSync(p, MAX_LOG_BYTES);
    if (txt == null) return { ok: false, error: "read-failed", path: p };

    const arr = txt.split("\n");
    const slice = arr.slice(Math.max(0, arr.length - n));
    return { ok: true, path: p, lines: slice.length, text: slice.join("\n") };
  } catch (e) {
    return { ok: false, error: String(e?.message || e), path: p };
  }
}

function requestUpstream(req, res) {
  const urlRaw = req.url || "/";
  const url = rewriteUrlTokenParams(urlRaw);

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
  };

  if (proxyTimeoutMs > 0) {
    options.timeout = proxyTimeoutMs;
  }

  if (upstreamProtocol === "https") {
    options.rejectUnauthorized = !upstreamInsecure;
  }

  const proxyReq = client.request(options, (proxyRes) => {
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

  if (proxyTimeoutMs > 0) {
    proxyReq.on("timeout", () => {
      try {
        proxyReq.destroy(new Error("upstream timeout"));
      } catch {}
    });
  }

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
            console.log("[railway-start] detected auth token missing; enabling passGatewayTokenToChild for next restart");
          }
        }

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
    const urlRaw = req.url || "/";
    const urlPath = String(urlRaw).split("?")[0] || "/";

    if (rootHealthOk && urlPath === "/" && isLikelyHealthProbe(req)) {
      return serveTextHeadAware(req, res, 200, "ok");
    }

    if (urlPath === "/debug" && !debugPublic) {
      const check = checkDebugToken(req);
      if (!check.ok) return serveTextHeadAware(req, res, 401, "unauthorized");
    }

    if (urlPath === "/openclaw-log" && !debugPublic) {
      const check = checkDebugToken(req);
      if (!check.ok) return serveTextHeadAware(req, res, 401, "unauthorized");
    }

    if (
      enforceProxyToken &&
      urlPath !== "/health" &&
      urlPath !== "/ready" &&
      urlPath !== "/debug" &&
      urlPath !== "/openclaw-log" &&
      !isPublicUiPath(urlPath)
    ) {
      const check = checkProxyToken(req);
      if (!check.ok) {
        console.log("[railway-start] proxy token blocked", String(req.method || "GET"), urlPath, "reason", check.reason);
        return serveTextHeadAware(req, res, 401, "unauthorized");
      }
    }

    if (urlPath === "/health") return serveTextHeadAware(req, res, 200, "ok");

    if (urlPath === "/ready") {
      const ok = await isOpenClawReadyFast();
      return serveTextHeadAware(req, res, ok ? 200 : 503, ok ? "ready" : "not-ready");
    }

    if (urlPath === "/openclaw-log") {
      const u = new URL(String(req.url || "/openclaw-log"), "http://local.invalid");
      const linesRaw = u.searchParams.get("lines") || "600";
      const n = clamp(Number(linesRaw) || 600, 10, 5000);

      const p = findLatestOpenClawLog();
      const t = tailFile(p, n);

      if (!t.ok) {
        return serveJsonHeadAware(req, res, 404, {
          ok: false,
          error: t.error || "no-log",
          path: t.path || p || "",
          hint: "OpenClaw logs are usually under /tmp/openclaw/openclaw-YYYY-MM-DD.log",
        });
      }

      res.statusCode = 200;
      res.setHeader("content-type", "text/plain");
      const m = String(req.method || "GET").toUpperCase();
      if (m === "HEAD") return res.end();
      res.end(t.text || "");
      return;
    }

    if (urlPath === "/debug") {
      const sig = await isOpenClawReadySignal();
      const tfp = tokenFingerprint(token);
      const akp = tokenFingerprint(envStr("ANTHROPIC_API_KEY", "").trim());

      return serveJsonHeadAware(req, res, 200, {
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
        workspaceDir,
        mirrorDirs,

        enforceTokenAuth,
        injectGatewayTokenHeaders,
        passGatewayTokenToChild,
        childUsesTokenAuth,

        tokenHeaderCompat,
        legacyGatewayTokenHeader,

        autoPassTokenOnAuthError,

        enforceProxyToken,
        debugPublic,
        debugRequiresToken,
        selfSanitize,
        selfSanitizeStrict,

        controlUiAllowInsecureAuth,

        rewriteQueryTokens,

        stripOpenaiEnv,
        enableOpenaiProfile,

        tokenFingerprint: tfp,
        anthropicKeyFingerprint: akp,

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
        wsTokenProtocolMode,

        rootHealthOk,

        trustedProxies: trusted,
        outTail: outRing.slice(-120),
        errTail: errRing.slice(-120),
      });
    }

    if (!claw && !clawStarting) {
      setTimeout(() => startOpenClawLoop(), 0);
    }

    if (!proxyEnabled) {
      return serveTextHeadAware(req, res, 404, "Proxy disabled. Use /health /ready /debug /openclaw-log.");
    }

    const isReady = await isOpenClawReadyFast();
    if (!isReady) return serveTextHeadAware(req, res, 503, "OpenClaw is not ready yet. Check /debug.");

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
      const urlRaw = req.url || "/";
      const urlPath = String(urlRaw).split("?")[0] || "/";

      if (urlPath === "/debug" && !debugPublic) {
        const check = checkDebugToken(req);
        if (!check.ok) return destroyBoth("debug token rejected");
      }

      // Proxy token check happens before URL rewrite
      if (enforceProxyToken && urlPath !== "/debug" && !isPublicUiPath(urlPath)) {
        const check = checkProxyToken(req);
        if (!check.ok) {
          console.log("[railway-start] proxy token blocked WS", String(req.method || "GET"), urlPath, "reason", check.reason);
          return destroyBoth("proxy token rejected");
        }
      }

      if (!proxyEnabled) return destroyBoth("proxy disabled");

      const isReady = await isOpenClawReadyFast();
      if (!isReady) return destroyBoth("upstream not ready");

      const urlRewritten = rewriteUrlTokenParams(urlRaw);
      const url = injectGatewayTokenIntoUpstreamWsPath(urlRewritten);

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

        let safeHeaders = filterHopByHopResponseHeaders(upstreamRes.headers, { keepWsHandshake: true });
        safeHeaders = sanitizeWsHandshakeResponseHeaders(safeHeaders);

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

        socket.pipe(upstreamSocket);
        upstreamSocket.pipe(socket);
      });

      upstreamReq.on("error", (e) => destroyBoth(`upstream request error: ${e?.message || e}`));

      upstreamReq.end();
    } catch (e) {
      destroyBoth(`upgrade handler exception: ${e?.message || e}`);
    }
  });

  server.listen(externalPort, "0.0.0.0", () => {
    console.log("[railway-start] public server listening on 0.0.0.0:" + externalPort);
    console.log("[railway-start] endpoints: /health /ready /debug /openclaw-log");
    console.log("[railway-start] proxyEnabled =", proxyEnabled ? "yes" : "no");
    if (proxyEnabled) {
      console.log("[railway-start] proxying other routes to", `${upstreamProtocol}://${upstreamHost}:${internalPort}`);
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
