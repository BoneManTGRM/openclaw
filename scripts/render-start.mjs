// scripts/render-start.mjs
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

console.log("[render-start] starting");

const port = String(process.env.PORT || "10000");
const stateDir = process.env.OPENCLAW_STATE_DIR || "/data/.openclaw";

console.log("[render-start] PORT =", port);
console.log("[render-start] OPENCLAW_STATE_DIR =", stateDir);

// Write config into BOTH common filenames to maximize compatibility.
const configPathA = path.join(stateDir, "openclaw.json");
const configPathB = path.join(stateDir, "config.json");

function readJsonIfExists(p) {
  try {
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (e) {
    console.log(`[render-start] could not read ${p}: ${e?.message || e}`);
    return null;
  }
}

function uniq(arr) {
  return Array.from(new Set((arr || []).filter(Boolean)));
}

function writeJson(p, obj) {
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), "utf8");
  console.log(`[render-start] wrote ${p}`);
}

try {
  fs.mkdirSync(stateDir, { recursive: true });
  console.log("[render-start] ensured state dir exists");
} catch (e) {
  console.log(`[render-start] failed to create state dir: ${e?.message || e}`);
}

const base = readJsonIfExists(configPathA) || readJsonIfExists(configPathB) || {};
base.gateway = base.gateway || {};

// Trust Render internal proxy ranges plus localhost.
const desiredTrustedProxies = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.1",
  "::1",
];

base.gateway.trustedProxies = uniq([
  ...(Array.isArray(base.gateway.trustedProxies) ? base.gateway.trustedProxies : []),
  ...desiredTrustedProxies,
]);

// Keep your existing token based auth if present.
if (process.env.OPENCLAW_GATEWAY_TOKEN) {
  base.gateway.auth = { mode: "token", token: process.env.OPENCLAW_GATEWAY_TOKEN };
}

base.gateway.port = Number(port);

try {
  writeJson(configPathA, base);
  writeJson(configPathB, base);
} catch (e) {
  console.log(`[render-start] failed writing config: ${e?.message || e}`);
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

console.log("[render-start] exec:", ["node", ...args].join(" "));
const child = spawn("node", args, { stdio: "inherit" });

child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error("[render-start] failed to start:", err);
  process.exit(1);
});
