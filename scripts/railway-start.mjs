// scripts/railway-start.mjs
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import net from "node:net";
import { spawn, execSync } from "node:child_process";

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
  const raw = String(process.env[name] || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
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
      try { sock.destroy(); } catch {}
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.on("connect", () => done(true));
    sock.on("timeout", () => done(false));
    sock.on("error", () => done(false));
  });
}

function whichOpenClaw() {
  try {
    const p = execSync("which openclaw", { encoding: "utf8" }).trim();
    if (p) return p;
    return null;
  } catch {
    return null;
  }
}

const externalPort = envInt("PORT", 8080);
const internalPort = envInt("OPENCLAW_INTERNAL_PORT", 8081);

const token = String(process.env.OPENCLAW_GATEWAY_TOKEN || "").trim();
const enforceTokenAuth = envBool("OPENCLAW_ENFORCE_TOKEN_AUTH", false);

const candidates = [
  process.env.OPENCLAW_STATE_DIR,
  "/data/.openclaw",
  "/home/node/.openclaw",
  "/tmp/.openclaw",
].filter(Boolean);

let stateDir = candidates[0] || "/home/node/.openclaw";
for (const dir of candidates) {
  if (canWriteDir(dir)) {
    stateDir = dir;
    break;
  }
}

console.log("[railway-start] external PORT =", externalPort);
console.log("[railway-start] internal OpenClaw port =", internalPort);
console.log("[railway-start] chosen stateDir =", stateDir);
console.log("[railway-start] token present =", token ? "yes" : "no");
console.log("[railway-start] enforce token auth =", enforceTokenAuth ? "yes" : "no");

safeMkdir(stateDir);

const configA = path.join(stateDir, "openclaw.json");
const configB = path.join(stateDir, "config.json");

const base = readJsonIfExists(configA) || readJsonIfExists(configB) || {};
base.gateway = base.gateway || {};
base.gateway.port = Number(internalPort);
base.gateway.bind = "127.0.0.1";
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

function spawnOpenClawProcess() {
  const childEnv = { ...process.env, OPENCLAW_STATE_DIR: stateDir };

  const openclawPath = whichOpenClaw();
  if (openclawPath) {
    const args = [
      "gateway",
      "--allow-unconfigured",
      "--bind",
      "127.0.0.1",
      "--port",
      String(internalPort),
    ];
    console.log("[railway-start] exec:", ["openclaw", ...args].join(" "));
    return spawn("openclaw", args, { stdio: ["ignore", "pipe", "pipe"], env: childEnv });
  }

  // Fallback: run the node entrypoint directly if openclaw binary is missing
  const entry = "dist/index.js";
  if (!fs.existsSync(entry)) {
    throw new Error("Neither openclaw binary nor dist/index.js found. Build output missing.");
  }

  const args = [
    entry,
    "gateway",
    "--allow-unconfigured",
    "--bind",
    "127.0.0.1",
    "--port",
    String(internalPort),
  ];
  console.log("[railway-start] exec:", ["node", ...args].join(" "));
  return spawn("node", args, { stdio: ["ignore", "pipe", "pipe"], env: childEnv });
}

function startOpenClaw() {
  if (clawStarting || claw) {
    console.log("[railway-start] OpenClaw already starting or running, skipping");
    return;
  }

  clawStarting = true;
  clawReady = false;

  try {
    claw = spawnOpenClawProcess();
    console.log("[railway-start] OpenClaw spawned PID:", claw.pid);
  } catch (e) {
    console.error("[railway-start] Failed to spawn OpenClaw:", e?.message || e);
    claw = null;
    clawStarting = false;
    setTimeout(startOpenClaw, 3000);
    return;
  }

  const markReadyFromLine = (s) => {
    const t = String(s || "").toLowerCase();
    if (t.includes("listening") || t.includes("started") || t.includes("ready")) {
      clawReady = true;
    }
  };

  claw.stdout.on("data", (data) => {
    const lines = data.toString().split("\n").filter(Boolean);
    for (const ln of lines) {
      console.log("[openclaw]", ln);
      markReadyFromLine(ln);
    }
  });

  claw.stderr.on("data", (data) => {
    const lines = data.toString().split("\n").filter(Boolean);
    for (const ln of lines) {
      console.error("[openclaw ERROR]", ln);
      markReadyFromLine(ln);
    }
  });

  claw.on("exit", (code, signal) => {
    console.log("[railway-start] OpenClaw exited code:", code, "signal:", signal);
    claw = null;
    clawStarting = false;
    clawReady = false;
    setTimeout(startOpenClaw, 3000);
  });

  claw.on("error", (err) => {
    console.error("[railway-start] OpenClaw process error:", err?.message || err);
    claw = null;
    clawStarting = false;
    clawReady = false;
    setTimeout(startOpenClaw, 3000);
  });

  // Done starting attempt
  clawStarting = false;
}

// Public server so Railway can healthcheck the container
const server = http.createServer(async (req, res) => {
  const url = req.url || "/";

  if (url === "/health") {
    res.statusCode = 200;
    res.setHeader("content-type", "text/plain");
    res.end("ok");
    return;
  }

  if (url === "/ready") {
    const ok = await tcpCheck("127.0.0.1", internalPort, 800);
    res.statusCode = ok ? 200 : 503;
    res.setHeader("content-type", "text/plain");
    res.end(ok ? "ready" : "not-ready");
    return;
  }

  if (url === "/debug") {
    const ok = await tcpCheck("127.0.0.1", internalPort, 800);
    res.statusCode = 200;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({
      externalPort,
      internalPort,
      clawReady,
      clawRunning: !!claw,
      clawPid: claw?.pid || null,
      tcpCheck: ok,
      stateDir,
      hasOpenclawBinary: !!whichOpenClaw(),
      enforceTokenAuth,
    }, null, 2));
    return;
  }

  const isReady = await tcpCheck("127.0.0.1", internalPort, 500);
  if (!isReady) {
    res.statusCode = 503;
    res.setHeader("content-type", "text/plain");
    res.end("OpenClaw is not ready yet. Check /debug.");
    return;
  }

  const proxyReq = http.request(
    {
      hostname: "127.0.0.1",
      port: internalPort,
      method: req.method,
      path: url,
      headers: {
        ...req.headers,
        "x-forwarded-proto": "https",
        "x-forwarded-host": req.headers.host || "",
        "x-forwarded-for": req.socket.remoteAddress || "",
      },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );

  proxyReq.on("error", (err) => {
    console.log("[railway-start] Proxy error:", err.message);
    res.statusCode = 502;
    res.setHeader("content-type", "text/plain");
    res.end(`Bad gateway: ${err?.message || err}. Check /debug.`);
  });

  req.pipe(proxyReq);
});

// Simple TCP tunnel for WebSocket upgrade
server.on("upgrade", (req, socket, head) => {
  const upstream = net.connect(internalPort, "127.0.0.1", () => {
    upstream.write(
      [
        `${req.method} ${req.url} HTTP/${req.httpVersion}`,
        ...Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`),
        "",
        "",
      ].join("\r\n")
    );
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream).pipe(socket);
  });

  upstream.on("error", (err) => {
    console.log("[railway-start] WebSocket upgrade error:", err.message);
    try { socket.destroy(); } catch {}
  });
});

server.listen(externalPort, "0.0.0.0", () => {
  console.log("[railway-start] public server listening on 0.0.0.0:" + externalPort);
  console.log("[railway-start] endpoints: /health /ready /debug");
  console.log("[railway-start] proxying other routes to 127.0.0.1:" + internalPort);
  setTimeout(startOpenClaw, 500);
});
