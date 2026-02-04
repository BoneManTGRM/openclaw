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

function envBool(name, defaultValue = false) {
  const v = String(process.env[name] || "").trim().toLowerCase();
  if (!v) return defaultValue;
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

function pickWipStateDir() {
  const candidates = [
    process.env.OPENCLAW_STATE_DIR,
    "/data/.openclaw",
    "/home/node/.openclaw",
    "/tmp/.openclaw",
  ].filter(Boolean);

  let chosen = candidates[0] || "/home/node/.openclaw";
  for (const dir of candidates) {
    if (canWriteDir(dir)) {
      chosen = dir;
      break;
    }
  }
  return chosen;
}

// Railway external port
const publicPort = Number(process.env.PORT || "8080");

// Internal port for OpenClaw (not exposed directly)
const internalPort = Number(process.env.OPENCLAW_INTERNAL_PORT || "3333");

// Token auth for Control UI, optional
const token = String(process.env.OPENCLAW_GATEWAY_TOKEN || "").trim();
const enforceTokenAuth = envBool("OPENCLAW_ENFORCE_TOKEN_AUTH", false);

const stateDir = pickWipStateDir();

console.log("[railway-start] publicPort =", publicPort);
console.log("[railway-start] internalPort =", internalPort);
console.log("[railway-start] chosen stateDir =", stateDir);
console.log("[railway-start] token present =", token ? "yes" : "no");
console.log("[railway-start] enforce token auth =", enforceTokenAuth ? "yes" : "no");

safeMkdir(stateDir);

const configA = path.join(stateDir, "openclaw.json");
const configB = path.join(stateDir, "config.json");

// Merge existing config (prefer A then B)
const base = readJsonIfExists(configA) || readJsonIfExists(configB) || {};
base.gateway = base.gateway || {};

// IMPORTANT: OpenClaw listens on internalPort only
base.gateway.port = internalPort;

// Bind so wrapper can reach it
// 127.0.0.1 is fine because wrapper runs in same container
base.gateway.bind = "127.0.0.1";

// Trusted proxies for Railway and common private ranges
base.gateway.trustedProxies = uniq([
  ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
  "100.64.0.0/10",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.1/32",
  "::1/128",
]);

// Token auth optional
if (enforceTokenAuth && token) {
  base.gateway.auth = base.gateway.auth || {};
  base.gateway.auth.mode = "token";
  base.gateway.auth.token = token;
  console.log("[railway-start] gateway auth enabled (token)");
} else {
  if (base.gateway.auth) {
    delete base.gateway.auth;
    console.log("[railway-start] gateway auth disabled");
  }
}

const wroteA = safeWriteJson(configA, base);
const wroteB = safeWriteJson(configB, base);

if (!wroteA && !wroteB) {
  console.log("[railway-start] warning: could not write config files, continuing anyway");
}

// Spawn OpenClaw gateway
const clawArgs = [
  "dist/index.js",
  "gateway",
  "--allow-unconfigured",
  "--bind",
  "127.0.0.1",
  "--port",
  String(internalPort),
];

const childEnv = {
  ...process.env,
  OPENCLAW_STATE_DIR: stateDir,
};

console.log("[railway-start] spawning openclaw:", ["node", ...clawArgs].join(" "));
console.log("[railway-start] env OPENCLAW_STATE_DIR =", childEnv.OPENCLAW_STATE_DIR);

const claw = spawn("node", clawArgs, { stdio: "inherit", env: childEnv });

claw.on("exit", (code) => {
  console.log("[railway-start] openclaw exited with", code);
  process.exit(code ?? 0);
});
claw.on("error", (err) => {
  console.error("[railway-start] openclaw spawn error:", err);
  process.exit(1);
});

// Simple reverse proxy that also supports websocket upgrades
function proxyHttp(req, res) {
  const options = {
    host: "127.0.0.1",
    port: internalPort,
    method: req.method,
    path: req.url,
    headers: { ...req.headers },
  };

  const upstream = http.request(options, (upRes) => {
    res.writeHead(upRes.statusCode || 502, upRes.headers);
    upRes.pipe(res);
  });

  upstream.on("error", (e) => {
    res.statusCode = 502;
    res.setHeader("content-type", "text/plain");
    res.end("Bad gateway: " + (e?.message || String(e)));
  });

  req.pipe(upstream);
}

function proxyWebSocket(req, socket, head) {
  const upstream = net.connect(internalPort, "127.0.0.1", () => {
    upstream.write(
      `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n` +
        Object.entries(req.headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\r\n") +
        "\r\n\r\n"
    );

    if (head && head.length) upstream.write(head);

    socket.pipe(upstream);
    upstream.pipe(socket);
  });

  upstream.on("error", () => {
    try {
      socket.destroy();
    } catch {}
  });
}

// Public server on Railway PORT
const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.statusCode = 200;
    res.setHeader("content-type", "text/plain");
    res.end("ok");
    return;
  }
  proxyHttp(req, res);
});

server.on("upgrade", (req, socket, head) => {
  proxyWebSocket(req, socket, head);
});

server.listen(publicPort, "0.0.0.0", () => {
  console.log("[railway-start] public server listening on", publicPort);
  console.log("[railway-start] health endpoint is /health");
  console.log("[railway-start] proxying to openclaw on", internalPort);
});
