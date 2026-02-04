// scripts/railway-start.mjs
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

console.log("[railway-start] starting");

const port = String(process.env.PORT || "10000");
const stateDir = process.env.OPENCLAW_STATE_DIR || "/data/.openclaw";
const token = process.env.OPENCLAW_GATEWAY_TOKEN || "";

const configA = path.join(stateDir, "openclaw.json");
const configB = path.join(stateDir, "config.json");

function readJsonIfExists(p) {
  try {
    if (!fs.existsSync(p)) return {};
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (e) {
    console.log(`[railway-start] could not read ${p}: ${e?.message || e}`);
    return {};
  }
}

function writeJson(p, obj) {
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), "utf8");
  console.log(`[railway-start] wrote ${p}`);
}

function uniq(arr) {
  return Array.from(new Set((arr || []).filter(Boolean)));
}

fs.mkdirSync(stateDir, { recursive: true });

// Merge with any existing config so we do not wipe other settings
const base = {
  ...readJsonIfExists(configA),
  ...readJsonIfExists(configB),
};

base.gateway = base.gateway || {};

// Port must match Railway PORT
base.gateway.port = Number(port);

// Trust common proxy ranges so websocket is treated correctly behind Railway
base.gateway.trustedProxies = uniq([
  ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.1",
  "::1",
]);

// Enforce token auth so you can pair from the browser
if (token) {
  base.gateway.auth = base.gateway.auth || {};
  base.gateway.auth.mode = "token";
  base.gateway.auth.token = token;
}

writeJson(configA, base);
writeJson(configB, base);

// Start OpenClaw
const args = [
  "dist/index.js",
  "gateway",
  "--allow-unconfigured",
  "--bind",
  "lan",
  "--port",
  port,
];

console.log("[railway-start] exec:", ["node", ...args].join(" "));
const child = spawn("node", args, { stdio: "inherit" });

child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error("[railway-start] spawn error:", err);
  process.exit(1);
});
