// scripts/railway-start.mjs
// Railway friendly OpenClaw launcher and proxy.
//
// What this file does
// - Starts OpenClaw gateway on an internal port (default 8081) and proxies Railway PORT to it.
// - Optionally lets OpenClaw bind directly to Railway PORT when OPENCLAW_LISTEN_ON_EXTERNAL=1.
// - Writes a safe OpenClaw config (openclaw.json + config.json) with gateway.port and gateway.trustedProxies.
// - Prevents pairing-required loops on Railway by stripping proxy-derived headers in selfSanitize mode.
// - Fixes loopback Host header mismatch that can flip OpenClaw into "remote" mode.
// - Optionally writes auth-profiles.json from env vars or ANTHROPIC_API_KEY / OPENAI_API_KEY.
//
// Notes for Railway reliability
// - Best default is proxy mode: wrapper binds PORT, OpenClaw binds internal port.
// - If you enable OPENCLAW_LISTEN_ON_EXTERNAL=1, wrapper server is disabled to avoid port collisions.
//
// Key fixes in this version
// 1) Host header parsing is IPv6 safe (handles [::1]:port correctly).
// 2) Adds server "clientError" handler to avoid crashes on malformed requests.
// 3) Tightens readiness and restart behavior (kills child on TCP-not-ready).
// 4) Keeps selfSanitize behavior: strips proxy-derived headers and does not add x-forwarded-* back.
// 5) Keeps OpenClaw bind logic: proxy mode prefers loopback, fallback to lan after failures.
// 6) WebSocket proxy now handles non-101 upstream responses safely (no hanging sockets).
//
// Update in this version
// - Do NOT write gateway.auth unless token auth is explicitly enabled.
//   Some OpenClaw builds reject gateway.auth.mode or the "none" enum and will exit on boot.

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
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
  const override = String(process.env.OPENCLAW_TRUSTED_PROXIES || "").trim();
  const base = [
    "100.64.0.0/10",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.1/32",
    "::1/128",
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
    const done = (ok) => {
      try {
        sock.destroy();
      } catch {}
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.on("connect", () => done(true));
    sock.on("timeout", () => done(false));
    sock.on("error", () => done(false));
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
// Supports: spaces, single quotes, double quotes, backslash escapes inside double quotes.
function shellSplit(cmdline) {
  const s = String(cmdline || "").trim();
  if (!s) return [];
  const out = [];
  let cur = "";
  let q = null; // "'" | '"' | null
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

// Railway port (public)
const externalPort = envInt("PORT", 8080);

// Internal port for OpenClaw when proxying (default)
const internalPortDefault = envInt("OPENCLAW_INTERNAL_PORT", 8081);

// If OPENCLAW_LISTEN_ON_EXTERNAL=1, OpenClaw binds to externalPort.
// In that mode this wrapper MUST NOT bind to externalPort.
const openclawListenOnExternal = envBool("OPENCLAW_LISTEN_ON_EXTERNAL", false);

const internalPort = openclawListenOnExternal ? externalPort : internalPortDefault;

const token = envStr("OPENCLAW_GATEWAY_TOKEN", "");
const enforceTokenAuth = envBool("OPENCLAW_ENFORCE_TOKEN_AUTH", false);

// Self sanitize config to a strict minimal object that cannot contain unknown keys.
const selfSanitize = envBool("OPENCLAW_SELF_SANITIZE", true);

let startupTimeoutMs = envInt("OPENCLAW_STARTUP_TIMEOUT_MS", 120000);
startupTimeoutMs = clamp(startupTimeoutMs, 15000, 600000);

const watchdogIntervalMs = envInt("OPENCLAW_WATCHDOG_INTERVAL_MS", 8000);
const proxyTimeoutMs = envInt("OPENCLAW_PROXY_TIMEOUT_MS", 60000);

// Upstream protocol for proxy mode
const upstreamProtocol =
  envStr("OPENCLAW_UPSTREAM_PROTOCOL", "http").toLowerCase() === "https" ? "https" : "http";
const upstreamHost = envStr("OPENCLAW_UPSTREAM_HOST", "127.0.0.1");

// Optional: override forwarded host/proto if you want hardcoding.
const forwardedProtoOverride = envStr("OPENCLAW_FORWARDED_PROTO", "");
const forwardedHostOverride = envStr("OPENCLAW_FORWARDED_HOST", "");

// Optional: if set, force the Host header sent upstream (rare)
const upstreamHostHeaderOverride = envStr("OPENCLAW_UPSTREAM_HOST_HEADER", "");

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

const candidates = [
  process.env.OPENCLAW_STATE_DIR,
  "/data/.openclaw",
  "/home/node/.openclaw",
  "/tmp/.openclaw",
].filter(Boolean);

let stateDir = "/tmp/.openclaw";

if (process.env.OPENCLAW_STATE_DIR && canWriteDir(process.env.OPENCLAW_STATE_DIR)) {
  stateDir = process.env.OPENCLAW_STATE_DIR;
} else {
  for (const dir of candidates) {
    if (canWriteDir(dir)) {
      stateDir = dir;
      break;
    }
  }
}

console.log("[railway-start] external PORT =", externalPort);
console.log("[railway-start] internal OpenClaw port =", internalPort);
console.log("[railway-start] proxyEnabled =", proxyEnabled ? "yes" : "no");
console.log("[railway-start] openclawListenOnExternal =", openclawListenOnExternal ? "yes" : "no");
console.log("[railway-start] chosen stateDir =", stateDir);
console.log("[railway-start] token present =", token ? "yes" : "no");
console.log("[railway-start] enforce gateway token auth =", enforceTokenAuth ? "yes" : "no");
console.log("[railway-start] enforce proxy token =", enforceProxyToken ? "yes" : "no");
console.log("[railway-start] selfSanitize =", selfSanitize ? "yes" : "no");
console.log("[railway-start] startupTimeoutMs =", startupTimeoutMs);
console.log("[railway-start] bindPrimary =", bindPrimary, "bindFallback =", bindFallback);
console.log("[railway-start] OPENCLAW_SHELL_LOCAL_BIN =", useShellForLocalBin ? "yes" : "no");
console.log("[railway-start] OpenClaw force requested =", forceRequested ? "yes" : "no");
console.log("[railway-start] OpenClaw force enabled =", forceEnabled ? "yes" : "no");
console.log("[railway-start] upstream =", `${upstreamProtocol}://${upstreamHost}:${internalPort}`);

if (openclawListenOnExternal) {
  console.log("[railway-start] warning: OPENCLAW_LISTEN_ON_EXTERNAL=1 disables wrapper server");
  console.log("[railway-start] recommended default on Railway is proxy mode (OPENCLAW_LISTEN_ON_EXTERNAL=0)");
}

safeMkdir(stateDir);

const configA = path.join(stateDir, "openclaw.json");
const configB = path.join(stateDir, "config.json");

// Read existing config (if any) then sanitize.
const existing = readJsonIfExists(configA) || readJsonIfExists(configB) || {};
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

  // Only write auth settings if token auth is explicitly enabled.
  // Some OpenClaw builds reject gateway.auth.mode and/or the "none" enum.
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

  // Strip known-invalid keys
  delete base.trustProxy;
  delete base.trustedProxies;
  if (base.gateway) {
    delete base.gateway.trustProxy;
    delete base.gateway.trustProxies;
    delete base.gateway.pairingRequired;
  }

  // Only write auth settings if token auth is explicitly enabled.
  // Some OpenClaw builds reject gateway.auth.mode and/or the "none" enum.
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

safeWriteJson(configA, configToWrite);
safeWriteJson(configB, configToWrite);

// Optional: write OpenClaw agent auth store if provided.
// Priority:
// 1) OPENCLAW_AUTH_PROFILES_JSON (raw JSON string)
// 2) OPENCLAW_AUTH_PROFILES_B64  (base64 JSON)
// 3) OPENAI_API_KEY              (auto-generate minimal auth-profiles.json)
// 4) ANTHROPIC_API_KEY           (auto-generate minimal auth-profiles.json)
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

  const agentAuthDir = path.join(stateDir, "agents", "main", "agent");
  const authPath = path.join(agentAuthDir, "auth-profiles.json");

  safeMkdir(agentAuthDir);

  if (jsonRaw) {
    console.log("[railway-start] writing auth-profiles.json from OPENCLAW_AUTH_PROFILES_JSON");
    safeWriteText(authPath, jsonRaw);
    return;
  }

  if (b64) {
    console.log("[railway-start] writing auth-profiles.json from OPENCLAW_AUTH_PROFILES_B64");
    try {
      const buf = Buffer.from(b64, "base64");
      safeWriteText(authPath, buf.toString("utf8"));
    } catch (e) {
      console.log(`[railway-start] failed to decode OPENCLAW_AUTH_PROFILES_B64: ${e?.message || e}`);
    }
    return;
  }

  const authObj = {};
  if (openaiKey) authObj.openai = { apiKey: openaiKey };
  if (anthropicKey) authObj.anthropic = { apiKey: anthropicKey };

  console.log("[railway-start] auto-generating auth-profiles.json from API key env vars");
  safeWriteJson(authPath, authObj);
})();

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
      child.kill("SIGKILL");
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
  const args = [
    "gateway",
    "--allow-unconfigured",
    "--bind",
    String(bindMode),
    "--port",
    String(internalPort),
  ];

  if (forceEnabled) {
    args.push("--force");
  } else if (forceRequested && !forceEnabled) {
    console.log("[railway-start] OPENCLAW_FORCE=1 requested but lsof is missing, skipping --force");
  }

  return args;
}

function currentBindForAttempt(attempt) {
  return attempt >= 2 ? bindFallback : bindPrimary;
}

function spawnOpenClawProcess(bindMode) {
  const childEnv = { ...process.env, OPENCLAW_STATE_DIR: stateDir };

  const resolved = resolveOpenClawCommand();
  if (!resolved) {
    throw new Error(
      "Could not find OpenClaw entry. Missing node_modules/.bin/openclaw, openclaw.mjs, and dist/index.js."
    );
  }

  const args = [...resolved.argsPrefix, ...buildOpenClawArgs(bindMode)];

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

async function waitForOpenClawTcpReady(timeoutMs, child) {
  const start = Date.now();
  const deadline = start + timeoutMs;

  await sleep(800);

  let lastLogAt = 0;

  while (Date.now() < deadline) {
    if (child && child.exitCode != null) {
      console.log("[railway-start] child already exited while waiting, exitCode =", child.exitCode);
      return false;
    }

    const r = await isPortReadyAnyHost();
    if (r.ok) {
      console.log("[railway-start] TCP ready on host", r.host, "port", internalPort);
      return true;
    }

    const now = Date.now();
    if (now - lastLogAt > 5000) {
      lastLogAt = now;
      const elapsed = now - start;
      const remaining = Math.max(0, deadline - now);
      console.log(
        "[railway-start] waiting for TCP readiness",
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

  const markReadyFromLine = (s) => {
    const t = String(s || "").toLowerCase();
    if (t.includes("listening") || t.includes("started") || t.includes("ready")) {
      clawReady = true;
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
        markReadyFromLine(ln);
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
        markReadyFromLine(ln);
      }
    });
    claw.stderr.on("end", () => console.log("[railway-start] child stderr ended"));
  }

  claw.on("exit", (code, signal) => {
    console.log("[railway-start] OpenClaw exited code:", code, "signal:", signal);

    dumpRing("[railway-start][openclaw STDOUT]", outRing);
    dumpRing("[railway-start][openclaw STDERR]", errRing);

    if (myLoopId !== startLoopId) {
      console.log("[railway-start] Superseded by newer start attempt, not restarting");
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
      console.log("[railway-start] Superseded, not restarting");
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

  const becameReady = await waitForOpenClawTcpReady(startupTimeoutMs, claw);

  if (myLoopId !== startLoopId) {
    clawStarting = false;
    return;
  }

  if (!becameReady) {
    console.error("[railway-start] OpenClaw did not become TCP-ready in time, restarting");
    dumpRing("[railway-start][openclaw STDOUT]", outRing);
    dumpRing("[railway-start][openclaw STDERR]", errRing);

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
  console.log("[railway-start] OpenClaw is TCP-ready");
}

const proxyAgentHttp = new http.Agent({ keepAlive: true });
const proxyAgentHttps = new https.Agent({ keepAlive: true });

function normalizeToken(s) {
  return String(s || "").trim();
}

function checkProxyToken(req) {
  if (!enforceProxyToken) return { ok: true, reason: "disabled" };
  if (!token) return { ok: false, reason: "missing-server-token" };

  const hdr =
    normalizeToken(req.headers["x-openclaw-token"]) ||
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

// Headers that trigger OpenClaw proxy detection and can cause pairing loops behind Railway.
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
  const inboundIsLocal = isLocalHostHeader(inboundHost);

  // If proxying to loopback and inbound Host is not local, rewrite Host to local for OpenClaw.
  if (isLoopbackHost(upstreamHost) && !inboundIsLocal) {
    return buildLocalHostHeader(upstreamHost, internalPort);
  }

  return xfHost || inboundHost || "";
}

function buildForwardedHeaders(req) {
  const remoteAddr = req.socket?.remoteAddress || "";

  const dash = String.fromCharCode(45);
  const H_XFF = "x" + dash + "forwarded" + dash + "for";
  const H_XFP = "x" + dash + "forwarded" + dash + "proto";
  const H_XFH = "x" + dash + "forwarded" + dash + "host";
  const H_XFPORT = "x" + dash + "forwarded" + dash + "port";
  const H_XREAL = "x" + dash + "real" + dash + "ip";

  const priorXff = req.headers[H_XFF] || req.headers["x-forwarded-for"];
  const xff = priorXff ? `${priorXff}, ${remoteAddr}` : remoteAddr;

  const xfProto =
    forwardedProtoOverride ||
    req.headers[H_XFP] ||
    req.headers["x-forwarded-proto"] ||
    (req.socket?.encrypted ? "https" : "http");

  const xfHost =
    forwardedHostOverride ||
    req.headers[H_XFH] ||
    req.headers["x-forwarded-host"] ||
    req.headers.host ||
    "";

  const hopByHop = new Set([
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
  ]);

  const cleaned = {};
  for (const [k, v] of Object.entries(req.headers || {})) {
    if (!hopByHop.has(String(k).toLowerCase())) cleaned[k] = v;
  }

  cleaned.host = pickHostHeaderForUpstream(req, xfHost);

  // Self sanitize: strip proxy-derived headers and do not add x-forwarded-* back.
  if (selfSanitize) {
    const stripped = stripProxyDerivedHeaders(cleaned);
    stripped.host = cleaned.host || stripped.host || "";
    return stripped;
  }

  // Normal mode: add forwarding headers
  return {
    ...cleaned,
    [H_XFP]: String(xfProto),
    [H_XFH]: String(xfHost),
    [H_XFF]: String(xff),
    [H_XREAL]: String(remoteAddr),
    [H_XFPORT]: String(externalPort),
  };
}

async function isOpenClawReadyFast() {
  if (clawReady) return true;
  const r = await isPortReadyAnyHost();
  return r.ok;
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

function selectUpstreamClient() {
  return upstreamProtocol === "https" ? https : http;
}

function selectUpstreamAgent() {
  return upstreamProtocol === "https" ? proxyAgentHttps : proxyAgentHttp;
}

function requestUpstream(req, res) {
  const url = req.url || "/";
  const headers = buildForwardedHeaders(req);

  const client = selectUpstreamClient();
  const agent = selectUpstreamAgent();

  const insecure = envBool("OPENCLAW_UPSTREAM_INSECURE", false);

  const options = {
    agent,
    hostname: upstreamHost,
    port: internalPort,
    method: req.method,
    path: url,
    headers,
    timeout: proxyTimeoutMs,
  };

  // Only https supports rejectUnauthorized
  if (upstreamProtocol === "https") {
    options.rejectUnauthorized = !insecure;
  }

  const proxyReq = client.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on("timeout", () => {
    try {
      proxyReq.destroy(new Error("upstream timeout"));
    } catch {}
  });

  proxyReq.on("error", (err) => {
    console.log("[railway-start] Proxy error:", err?.message || err);
    serveText(res, 502, `Bad gateway: ${err?.message || err}. Check /debug.`);
  });

  req.pipe(proxyReq);
}

// If OpenClaw binds to externalPort, do not start wrapper server (port collision).
if (openclawListenOnExternal) {
  console.log("[railway-start] OPENCLAW_LISTEN_ON_EXTERNAL=1");
  console.log("[railway-start] wrapper HTTP server disabled to avoid EADDRINUSE");
  console.log("[railway-start] OpenClaw should serve /health /ready or its own endpoints");
  console.log("[railway-start] bind mode forced to lan in this mode");

  setTimeout(() => startOpenClawLoop(), 0);

  setInterval(async () => {
    if (!claw || clawStarting) return;
    const r = await isPortReadyAnyHost();
    if (r.ok) return;

    console.error("[railway-start] watchdog: OpenClaw TCP down, restarting");
    dumpRing("[railway-start][openclaw STDOUT]", outRing);
    dumpRing("[railway-start][openclaw STDERR]", errRing);

    const child = claw;
    claw = null;
    clawReady = false;
    killChild(child);

    restartAttempt = Math.max(1, restartAttempt);
    scheduleRestart(computeBackoffMs(1));
  }, watchdogIntervalMs).unref();

  function shutdown(reason) {
    console.log("[railway-start] shutdown:", reason);
    const child = claw;
    claw = null;
    if (child) killChild(child);
    setTimeout(() => process.exit(0), 1200);
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

  setInterval(() => {}, 1 << 30).unref();
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
      const r = await isPortReadyAnyHost();
      return serveJson(res, 200, {
        externalPort,
        internalPort,
        proxyEnabled,
        openclawListenOnExternal,
        upstreamProtocol,
        upstreamHost,
        upstreamHostHeaderOverride,
        clawReady,
        clawRunning: !!claw,
        clawPid: claw?.pid || null,
        tcpReady: r.ok,
        tcpHost: r.host,
        stateDir,
        enforceTokenAuth,
        enforceProxyToken,
        selfSanitize,
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

  // Avoid timeouts killing long-lived requests and websocket upgrades
  server.requestTimeout = 0;
  server.headersTimeout = Math.max(server.headersTimeout || 60000, 65000);
  server.keepAliveTimeout = Math.max(server.keepAliveTimeout || 5000, 65000);

  // Avoid process crash from malformed HTTP
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
    try {
      const url = req.url || "/";

      if (enforceProxyToken && url !== "/debug" && !isPublicUiPath(url)) {
        const check = checkProxyToken(req);
        if (!check.ok) {
          try {
            socket.destroy();
          } catch {}
          return;
        }
      }

      if (!proxyEnabled) {
        try {
          socket.destroy();
        } catch {}
        return;
      }

      const isReady = await isOpenClawReadyFast();
      if (!isReady) {
        try {
          socket.destroy();
        } catch {}
        return;
      }

      const headers = buildForwardedHeaders(req);

      const client = selectUpstreamClient();
      const agent = selectUpstreamAgent();
      const insecure = envBool("OPENCLAW_UPSTREAM_INSECURE", false);

      const options = {
        agent,
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
        options.rejectUnauthorized = !insecure;
      }

      const upstreamReq = client.request(options);

      // If upstream returns a normal HTTP response (not an upgrade), relay it and close.
      upstreamReq.on("response", (upstreamRes) => {
        try {
          const statusCode = upstreamRes.statusCode || 502;
          const statusMsg = upstreamRes.statusMessage || "";
          const lines = [
            `HTTP/${upstreamRes.httpVersion || "1.1"} ${statusCode} ${statusMsg}`.trim(),
            ...headersToLines(upstreamRes.headers),
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
            try {
              socket.destroy();
            } catch {}
          });

          upstreamRes.on("error", () => {
            try {
              socket.destroy();
            } catch {}
          });
        } catch {
          try {
            socket.destroy();
          } catch {}
        }
      });

      upstreamReq.on("upgrade", (upstreamRes, upstreamSocket) => {
        const lines = [
          `HTTP/${upstreamRes.httpVersion} ${upstreamRes.statusCode} ${upstreamRes.statusMessage || ""}`.trim(),
          ...headersToLines(upstreamRes.headers),
          "",
          "",
        ];
        socket.write(lines.join("\r\n"));

        if (head && head.length) upstreamSocket.write(head);

        socket.pipe(upstreamSocket).pipe(socket);

        socket.on("error", () => {
          try {
            upstreamSocket.destroy();
          } catch {}
        });

        upstreamSocket.on("error", () => {
          try {
            socket.destroy();
          } catch {}
        });
      });

      upstreamReq.on("timeout", () => {
        try {
          upstreamReq.destroy(new Error("upstream timeout"));
        } catch {}
        try {
          socket.destroy();
        } catch {}
      });

      upstreamReq.on("error", () => {
        try {
          socket.destroy();
        } catch {}
      });

      upstreamReq.end();
    } catch {
      try {
        socket.destroy();
      } catch {}
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
      const r = await isPortReadyAnyHost();
      if (r.ok) return;

      console.error("[railway-start] watchdog: OpenClaw TCP down, restarting");
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
    setTimeout(() => process.exit(0), 1200);
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
