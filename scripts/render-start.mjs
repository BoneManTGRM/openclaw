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

const child = spawn("node", args, { stdio: "inherit" });

child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error("[render-start] failed to start:", err);
  process.exit(1);
});
