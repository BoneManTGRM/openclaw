// scripts/railway-start.mjs
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";

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
    ? override.split(",").map((s) => s.trim()).filter(Boolean)
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

const externalPort = envInt("PORT", 8080);
const internalPort = envInt("OPENCLAW_INTERNAL_PORT", 8081);

const token = envStr("OPENCLAW_GATEWAY_TOKEN", "");
const enforceTokenAuth = envBool("OPENCLAW_ENFORCE_TOKEN_AUTH", false);

let startupTimeoutMs = envInt("OPENCLAW_STARTUP_TIMEOUT_MS", 120000);
startupTimeoutMs = clamp(startupTimeoutMs, 15000, 600000);

const watchdogIntervalMs = envInt("OPENCLAW_WATCHDOG_INTERVAL_MS", 8000);
const proxyTimeoutMs = envInt("OPENCLAW_PROXY_TIMEOUT_MS", 60000);

/**
 * IMPORTANT:
 * OpenClaw `gateway --bind` expects a MODE, not an IP.
 * Valid modes include: loopback, tailnet, lan, auto, custom
 * (See OpenClaw docs for the full list and meaning)
 */
const bindPrimary = envStr("OPENCLAW_BIND", "loopback");
const bindFallback = envStr("OPENCLAW_BIND_FALLBACK", "lan");

const useShellForLocalBin = envBool("OPENCLAW_SHELL_LOCAL_BIN", true);

// Optional: if you want this wrapper to enforce a token on inbound requests,
// set OPENCLAW_PROXY_ENFORCE_TOKEN=1 and OPENCLAW_GATEWAY_TOKEN=...
const enforceProxyToken = envBool("OPENCLAW_PROXY_ENFORCE_TOKEN", false);

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
console.log("[railway-start] chosen stateDir =", stateDir);
console.log("[railway-start] token present =", token ? "yes" : "no");
console.log("[railway-start] enforce gateway token auth =", enforceTokenAuth ? "yes" : "no");
console.log("[railway-start] enforce proxy token =", enforceProxyToken ? "yes" : "no");
console.log("[railway-start] startupTimeoutMs =", startupTimeoutMs);
console.log("[railway-start] bindPrimary =", bindPrimary, "bindFallback =", bindFallback);
console.log("[railway-start] OPENCLAW_SHELL_LOCAL_BIN =", useShellForLocalBin ? "yes" : "no");

safeMkdir(stateDir);

const configA = path.join(stateDir, "openclaw.json");
const configB = path.join(stateDir, "config.json");

const base = readJsonIfExists(configA) || readJsonIfExists(configB) || {};
base.gateway = base.gateway || {};

base.gateway.port = Number(internalPort);
base.gateway.trustedProxies = uniq([
  ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
  ...parseTrustedProxies(),
]);

if (enforceTokenAuth && token) {
  base.gateway.auth = base.gateway.auth || {};
  base.gateway.auth.mode = "token";
  base.gateway.auth.token = token;
  console.log("[railway-start] gateway auth enabled (token)");
} else {
  if (base.gateway.auth) delete base.gateway.auth;
  console.log("[railway-start] gateway auth disabled");
}

safeWriteJson(configA, base);
safeWriteJson(configB, base);

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
    console.log("[railway-start] using OPENCLAW_CMD override:", override);
    const parts = override.split(" ").filter(Boolean);
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

/**
 * OpenClaw expects bind MODEs here, not IPs.
 */
function buildOpenClawArgs(bindMode) {
  return [
    "gateway",
    "--force",
    "--allow-unconfigured",
    "--bind",
    String(bindMode),
    "--port",
    String(internalPort),
  ];
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
    const cmdLine = [resolved.cmd, ...args].join(" ");
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
  // Note: do not include 0.0.0.0 here. It is a bind address, not a connect target.
  const hosts = ["127.0.0.1", "localhost", "::1"];
  for (const h of hosts) {
    // eslint-disable-next-line no-await-in-loop
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
      const lines = data.toString().split("\n").map((x) => x.trimEnd()).filter(Boolean);
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
      const lines = data.toString().split("\n").map((x) => x.trimEnd()).filter(Boolean);
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

const proxyAgent = new http.Agent({ keepAlive: true });

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
  const bearer =
    auth.toLowerCase().startsWith("bearer ") ? normalizeToken(auth.slice(7)) : "";

  const got = hdr || bearer;
  if (!got) return { ok: false, reason: "missing-client-token" };
  if (got !== token) return { ok: false, reason: "bad-client-token" };

  return { ok: true, reason: "ok" };
}

function buildForwardedHeaders(req) {
  const remoteAddr = req.socket?.remoteAddress || "";
  const priorXff = req.headers["x-forwarded-for"];
  const xff = priorXff ? `${priorXff}, ${remoteAddr}` : remoteAddr;

  const xfProto = req.headers["x-forwarded-proto"] || "https";
  const xfHost = req.headers["x-forwarded-host"] || req.headers.host || "";

  // Remove hop-by-hop headers that should not be forwarded.
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

  return {
    ...cleaned,
    "x-forwarded-proto": String(xfProto),
    "x-forwarded-host": String(xfHost),
    "x-forwarded-for": String(xff),
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

const server = http.createServer(async (req, res) => {
  const url = req.url || "/";

  // Optional: enforce a token at the proxy edge too (useful if OpenClaw gateway auth is off)
  if (enforceProxyToken && url !== "/health" && url !== "/ready") {
    const check = checkProxyToken(req);
    if (!check.ok) {
      res.statusCode = 401;
      res.setHeader("content-type", "text/plain");
      res.end("unauthorized");
      return;
    }
  }

  // Friendly root so Railway "open app" does not look broken
  if (url === "/") {
    res.statusCode = 200;
    res.setHeader("content-type", "text/plain");
    res.end("ok\n/health\n/ready\n/debug\n");
    return;
  }

  if (url === "/health") {
    res.statusCode = 200;
    res.setHeader("content-type", "text/plain");
    res.end("ok");
    return;
  }

  if (url === "/ready") {
    const ok = await isOpenClawReadyFast();
    res.statusCode = ok ? 200 : 503;
    res.setHeader("content-type", "text/plain");
    res.end(ok ? "ready" : "not-ready");
    return;
  }

  if (url === "/debug") {
    const r = await isPortReadyAnyHost();
    serveJson(res, 200, {
      externalPort,
      internalPort,
      clawReady,
      clawRunning: !!claw,
      clawPid: claw?.pid || null,
      tcpReady: r.ok,
      tcpHost: r.host,
      stateDir,
      enforceTokenAuth,
      enforceProxyToken,
      startupTimeoutMs,
      watchdogIntervalMs,
      proxyTimeoutMs,
      restartAttempt,
      restartScheduled,
      clawStarting,
      bindPrimary,
      bindFallback,
      OPENCLAW_SHELL_LOCAL_BIN: useShellForLocalBin,
      outTail: outRing.slice(-120),
      errTail: errRing.slice(-120),
    });
    return;
  }

  if (!claw && !clawStarting) {
    setTimeout(() => startOpenClawLoop(), 0);
  }

  const isReady = await isOpenClawReadyFast();
  if (!isReady) {
    res.statusCode = 503;
    res.setHeader("content-type", "text/plain");
    res.end("OpenClaw is not ready yet. Check /debug.");
    return;
  }

  const headers = buildForwardedHeaders(req);

  const proxyReq = http.request(
    {
      agent: proxyAgent,
      hostname: "127.0.0.1",
      port: internalPort,
      method: req.method,
      path: url,
      headers,
      timeout: proxyTimeoutMs,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );

  proxyReq.on("timeout", () => {
    try {
      proxyReq.destroy(new Error("upstream timeout"));
    } catch {}
  });

  proxyReq.on("error", (err) => {
    console.log("[railway-start] Proxy error:", err?.message || err);
    res.statusCode = 502;
    res.setHeader("content-type", "text/plain");
    res.end(`Bad gateway: ${err?.message || err}. Check /debug.`);
  });

  req.pipe(proxyReq);
});

server.on("upgrade", async (req, socket, head) => {
  try {
    if (enforceProxyToken) {
      const check = checkProxyToken(req);
      if (!check.ok) {
        try {
          socket.destroy();
        } catch {}
        return;
      }
    }

    const isReady = await isOpenClawReadyFast();
    if (!isReady) {
      try {
        socket.destroy();
      } catch {}
      return;
    }

    const upstream = net.connect(internalPort, "127.0.0.1", () => {
      try {
        socket.setNoDelay(true);
        upstream.setNoDelay(true);
      } catch {}

      const headers = buildForwardedHeaders(req);

      upstream.write(
        [
          `${req.method} ${req.url} HTTP/${req.httpVersion}`,
          ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
          "",
          "",
        ].join("\r\n")
      );

      if (head && head.length) upstream.write(head);
      socket.pipe(upstream).pipe(socket);
    });

    upstream.on("error", (err) => {
      console.log("[railway-start] WebSocket upgrade error:", err?.message || err);
      try {
        socket.destroy();
      } catch {}
    });

    socket.on("error", () => {
      try {
        upstream.destroy();
      } catch {}
    });
  } catch {
    try {
      socket.destroy();
    } catch {}
  }
});

server.listen(externalPort, "0.0.0.0", () => {
  console.log("[railway-start] public server listening on 0.0.0.0:" + externalPort);
  console.log("[railway-start] endpoints: / /health /ready /debug");
  console.log("[railway-start] proxying other routes to 127.0.0.1:" + internalPort);

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
