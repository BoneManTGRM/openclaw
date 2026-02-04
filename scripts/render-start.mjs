import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const port = String(process.env.PORT || "10000");
const stateDir = process.env.OPENCLAW_STATE_DIR || "/home/node/.openclaw";
const configPath = path.join(stateDir, "openclaw.json");

// Trust Render's proxy network (10.x.x.x IPs from logs)
const config = {
  gateway: {
    bind: "lan",
    port: Number(port),
    trustedProxies: ["10.0.0.0/8", "127.0.0.1", "::1"],
    auth: process.env.OPENCLAW_GATEWAY_TOKEN
      ? { mode: "token", token: process.env.OPENCLAW_GATEWAY_TOKEN }
      : { mode: "none" },
  },
};

fs.mkdirSync(stateDir, { recursive: true });
fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf8");
console.log(`[render-start] wrote config ${configPath}`);

const args = [
  "dist/index.js",
  "gateway",
  "--allow-unconfigured",
  "--bind",
  "lan",
  "--port",
  port,
];

const child = spawn("node", args, { stdio: "inherit" });
child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error("[render-start] failed to start:", err);
  process.exit(1);
});
