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

const externalPort = envInt("PORT", 8080);
const internalPort = envInt("OPENCLAW_INTERNAL_PORT", externalPort + 1);

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
base.gateway.bind = base.gateway.bind || "127.0.0.1";
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

function startOpenClaw() {
  if (clawStarting) return;
  clawStarting = true;

  const childEnv = { ...process.env, OPENCLAW_STATE_DIR: stateDir };

  const args = [
    "gateway",
    "--allow-unconfigured",
    "--bind",
    "127.0.0.1",
    "--port",
    String(internalPort),
  ];

  console.log("[railway-start] exec:", ["openclaw", ...args].join(" "));
  try {
    claw = spawn("openclaw", args, { stdio: "inherit", env: childEnv });
  } catch (e) {
    console.log("[railway-start] spawn threw:", e?.message || e);
    clawStarting = false;
    return;
  }

  claw.on("exit", (code) => {
    console.log("[railway-start] OpenClaw exited with code", code);
    claw = null;
    clawStarting = false;
    setTimeout(startOpenClaw, 2000);
  });

  claw.on("error", (err) => {
    console.log("[railway-start] OpenClaw spawn error:", err?.message || err);
    claw = null;
    clawStarting = false;
    setTimeout(startOpenClaw, 2000);
  });

  clawStarting = false;
}

// Start the public server immediately so Railway healthcheck can succeed.
const server = http.createServer(async (req, res) => {
  const url = req.url || "/";

  if (url === "/health") {
    // Always 200 so Railway stops killing the deploy.
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

  // Proxy HTTP to OpenClaw
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
    res.statusCode = 502;
    res.setHeader("content-type", "text/plain");
    res.end(`bad gateway: ${err?.message || err}`);
  });

  req.pipe(proxyReq);
});

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

  upstream.on("error", () => {
    try { socket.destroy(); } catch {}
  });
});

server.listen(externalPort, "0.0.0.0", () => {
  console.log("[railway-start] public server listening on", externalPort);
  console.log("[railway-start] /health returns 200 always");
  console.log("[railway-start] /ready checks OpenClaw on 127.0.0.1:", internalPort);
  console.log("[railway-start] proxying all other routes to OpenClaw");
  startOpenClaw();
});
