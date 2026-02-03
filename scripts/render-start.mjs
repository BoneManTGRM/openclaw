// scripts/render-start.mjs
import { spawn } from "node:child_process";

const port = process.env.PORT || "10000";

const args = [
  "dist/index.js",
  "gateway",
  "--allow-unconfigured",
  "--bind",
  "lan",
  "--port",
  port,
];

console.log(`[render-start] PORT=${process.env.PORT} using port=${port}`);
console.log(`[render-start] exec: node ${args.join(" ")}`);

const child = spawn("node", args, { stdio: "inherit", env: process.env });

child.on("exit", (code, signal) => {
  console.log(`[render-start] exit code=${code} signal=${signal}`);
  process.exit(code ?? 0);
});
