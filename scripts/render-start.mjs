import fs from "node:fs";
import { spawn } from "node:child_process";

const port = String(process.env.PORT || "10000");
const token = process.env.OPENCLAW_GATEWAY_TOKEN;

// Write OpenClaw config into the default state dir used in your logs
const stateDir = "/home/node/.openclaw";
const configPath = `${stateDir}/openclaw.json`;

const config = {
  gateway: {
    // Keep your existing behavior
    bind: "lan",
    port: Number(port),

    // Trust Render’s internal proxy network (your logs show 10.x.x.x as remote)
    trustedProxies: ["10.0.0.0/8", "127.0.0.1", "::1"],

    // Enable auth so proxied clients are not rejected
    auth: token
      ? { mode: "token", token }
      : { mode: "none" },

    // Optional “break glass” if Control UI still insists on device pairing
    // allowInsecureAuth: true
  }
};

fs.mkdirSync(stateDir, { recursive: true });
fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf8");
console.log(`[render-start] wrote ${configPath}`);

const args = [
  "dist/index.js",
  "gateway",
  "--allow-unconfigured",
  "--bind",
  "lan",
  "--port",
  port,
];

spawn("node", args, { stdio: "inherit" }).on("exit", (code) =>
  process.exit(code ?? 0)
);
