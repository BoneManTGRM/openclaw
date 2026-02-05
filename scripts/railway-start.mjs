// scripts/railway-start.mjs
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import net from "net";
import { spawn } from "node:child_process";
import { execSync } from "node:child_process";

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

// Check if openclaw binary exists
function checkOpenClawBinary() {
  try {
    const result = execSync("which openclaw", { encoding: "utf8" }).trim();
    console.log("[railway-start] openclaw binary found at:", result);
    return true;
  } catch (e) {
    console.log("[railway-start] ERROR: openclaw binary not found in PATH");
    console.log("[railway-start] PATH:", process.env.PATH);
    return false;
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

function startOpenClaw() {
  if (clawStarting) {
    console.log("[railway-start] OpenClaw already starting, skipping");
    return;
  }
  
  if (!checkOpenClawBinary()) {
    console.log("[railway-start] Cannot start OpenClaw - binary not found");
    clawStarting = false;
    return;
  }
  
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

  console.log("[railway-start] Starting OpenClaw with command:", ["openclaw", ...args].join(" "));
  console.log("[railway-start] Environment: OPENCLAW_STATE_DIR =", stateDir);
  
  try {
    claw = spawn("openclaw", args, { 
      stdio: ["ignore", "pipe", "pipe"],
      env: childEnv 
    });
    
    console.log("[railway-start] OpenClaw process spawned with PID:", claw.pid);
    
    // Capture stdout
    claw.stdout.on("data", (data) => {
      const lines = data.toString().split("\n").filter(Boolean);
      lines.forEach(line => console.log("[openclaw]", line));
      
      // Check if OpenClaw is ready
      if (line.includes("listening") || line.includes("started")) {
        clawReady = true;
      }
    });
    
    // Capture stderr
    claw.stderr.on("data", (data) => {
      const lines = data.toString().split("\n").filter(Boolean);
      lines.forEach(line => console.error("[openclaw ERROR]", line));
    });
    
  } catch (e) {
    console.log("[railway-start] spawn threw:", e?.message || e);
    console.log("[railway-start] Full error:", e);
    clawStarting = false;
    return;
  }

  claw.on("exit", (code, signal) => {
    console.log("[railway-start] OpenClaw exited - code:", code, "signal:", signal);
    claw = null;
    clawStarting = false;
    clawReady = false;
    
    // Retry after 3 seconds
    console.log("[railway-start] Will retry OpenClaw in 3 seconds...");
    setTimeout(startOpenClaw, 3000);
  });

  claw.on("error", (err) => {
    console.log("[railway-start] OpenClaw spawn error:", err?.message || err);
    console.log("[railway-start] Full error:", err);
    claw = null;
    clawStarting = false;
    clawReady = false;
    
    // Retry after 3 seconds
    setTimeout(startOpenClaw, 3000);
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
  
  if (url === "/debug") {
    const ok = await tcpCheck("127.0.0.1", internalPort, 800);
    res.statusCode = 200;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({
      externalPort,
      internalPort,
      clawReady,
      clawProcess: claw ? "running" : "not running",
      clawPid: claw?.pid || null,
      tcpCheck: ok,
      stateDir,
    }, null, 2));
    return;
  }

  // Check if OpenClaw is reachable before proxying
  const isReady = await tcpCheck("127.0.0.1", internalPort, 500);
  if (!isReady) {
    res.statusCode = 503;
    res.setHeader("content-type", "text/plain");
    res.end("OpenClaw is not ready yet. Check /debug for status or /ready for health.");
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
    console.log("[railway-start] Proxy error:", err.message);
    res.statusCode = 502;
    res.setHeader("content-type", "text/plain");
    res.end(`Bad gateway: ${err?.message || err}. OpenClaw may not be running. Check /debug for details.`);
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

  upstream.on("error", (err) => {
    console.log("[railway-start] WebSocket upgrade error:", err.message);
    try { socket.destroy(); } catch {}
  });
});

server.listen(externalPort, "0.0.0.0", () => {
  console.log("[railway-start] ========================================");
  console.log("[railway-start] Public server listening on 0.0.0.0:" + externalPort);
  console.log("[railway-start] /health - Always returns 200 (for Railway)");
  console.log("[railway-start] /ready - Returns 200 if OpenClaw is reachable");
  console.log("[railway-start] /debug - Shows diagnostic information");
  console.log("[railway-start] All other routes proxy to OpenClaw on 127.0.0.1:" + internalPort);
  console.log("[railway-start] ========================================");
  
  // Wait a moment for server to be fully ready, then start OpenClaw
  setTimeout(startOpenClaw, 500);
});
