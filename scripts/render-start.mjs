// scripts/render-start.mjs
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

console.log("[render-start] starting");

const port = String(process.env.PORT || "10000");

// Use whatever you already set in Render.
// In your render.yaml you set OPENCLAW_STATE_DIR to /data/.openclaw
const stateDir = process.env.OPENCLAW_STATE_DIR || "/data/.openclaw";

// OpenClaw stores config in the state dir.
// Different builds sometimes look for different filenames, so we write both.
const configPathA = path.join(stateDir, "openclaw.json");
const configPathB = path.join(stateDir, "config.json");

function readJsonIfExists(p) {
  try {
    if (!fs.existsSync(p)) return null;
    const raw = fs.readFileSync(p, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function writeJson(p, obj) {
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), "utf8");
  console.log(`[render-start] wrote ${p}`);
}

function uniq(arr) {
  return Array.from(new Set(arr.filter(Boolean)));
}

fs.mkdirSync(stateDir, { recursive: true });

// Merge into any existing config instead of nuking it.
const base = readJsonIfExists(configPathA) || readJsonIfExists(configPathB) || {};
base.gateway = base.gateway || {};

// This is the key that fixes the 1008 behind Render proxy.
// Trust Render internal 10.x addresses plus localhost.
const desiredTrustedProxies = ["10.0.0.0/8", "127.0.0.1", "::1"];
base.gateway.trustedProxies = uniq([
  ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
  ...desiredTrustedProxies,
]);

// Keep auth simple.
// If you have OPENCLAW_GATEWAY_TOKEN, the UI should use it.
// If it is missing, OpenClaw may require pairing.
if (process.env.OPENCLAW_GATEWAY_TOKEN) {
  base.gateway.auth = base.gateway.auth || {};
  base.gateway.auth.mode = "token";
  base.gateway.auth.token = process.env.OPENCLAW_GATEWAY_TOKEN;
}

// Keep port in sync, but do not force any host or 0.0.0.0 flags here.
base.gateway.port = Number(port);

// Write both names to maximize compatibility.
writeJson(configPathA, base);
writeJson(configPathB, base);

// Start OpenClaw.
// Do not pass 0.0.0.0 anywhere.
// Only use bind mode + port.
const args = [
  "dist/index.js",
  "gateway",
  "--allow-unconfigured",
  "--bind",
  "lan",
  "--port",
  port,
];

console.log("[render-start] exec:", ["node", ...args].join(" "));

const child = spawn("node", args, { stdio: "inherit" });

child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error("[render-start] failed to start:", err);
  process.exit(1);
});
