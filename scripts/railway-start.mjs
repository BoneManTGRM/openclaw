// scripts/railway-start.mjs
import fs from "node:fs";
import path from "node:path";
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

const port = String(process.env.PORT || "8080");
const token = process.env.OPENCLAW_GATEWAY_TOKEN || "";

const candidates = [
  process.env.OPENCLAW_STATE_DIR,
  "/data/.openclaw",
  "/home/node/.openclaw",
  "/tmp/.openclaw",
].filter(Boolean);

let stateDir = null;
for (const dir of candidates) {
  if (canWriteDir(dir)) {
    stateDir = dir;
    break;
  }
}

if (!stateDir) {
  stateDir = "/tmp/.openclaw";
  console.log("[railway-start] no writable dir found in candidates, using", stateDir);
  safeMkdir(stateDir);
}

console.log("[railway-start] PORT =", port);
console.log("[railway-start] chosen stateDir =", stateDir);
console.log("[railway-start] token present =", token ? "yes" : "no");

const configA = path.join(stateDir, "openclaw.json");
const configB = path.join(stateDir, "config.json");

const base = readJsonIfExists(configA) || readJsonIfExists(configB) || {};
base.gateway = base.gateway || {};

base.gateway.port = Number(port);
base.gateway.bind = base.gateway.bind || "lan";

// Proxy trust for Railway style setups
base.gateway.trustedProxies = uniq([
  ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.1",
  "::1",
]);

// Require token auth
base.gateway.auth = base.gateway.auth || {};
base.gateway.auth.mode = "token";
base.gateway.auth.token = token;

const wroteA = safeWriteJson(configA, base);
const wroteB = safeWriteJson(configB, base);

if (!wroteA && !wroteB) {
  console.log("[railway-start] warning: could not write config files, continuing anyway");
}

const args = [
  "dist/index.js",
  "gateway",
  "--allow-unconfigured",
  "--bind",
  "lan",
  "--port",
  port,
];

const childEnv = {
  ...process.env,
  OPENCLAW_STATE_DIR: stateDir,
};

console.log("[railway-start] exec:", ["node", ...args].join(" "));
console.log("[railway-start] OPENCLAW_STATE_DIR for child =", childEnv.OPENCLAW_STATE_DIR);

const child = spawn("node", args, { stdio: "inherit", env: childEnv });

child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error("[railway-start] spawn error:", err);
  process.exit(1);
});
