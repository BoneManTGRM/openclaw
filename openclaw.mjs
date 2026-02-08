#!/usr/bin/env node

import module from "node:module";
import fs from "node:fs";
import path from "node:path";

// Enable Node compile cache when available
// https://nodejs.org/api/module.html#module-compile-cache
if (module.enableCompileCache && !process.env.NODE_DISABLE_COMPILE_CACHE) {
  try {
    module.enableCompileCache();
  } catch {
    // Ignore errors
  }
}

/**
 * Railway friendly defaults:
 * - Keep ALL OpenClaw state inside /home/node/.openclaw (ideal for a Railway volume mount)
 * - Keep workspace inside that same tree
 *
 * This also auto-fixes common bad values like /data/workspace that are not writable.
 */
const DEFAULT_STATE_DIR = "/home/node/.openclaw";
const DEFAULT_WORKSPACE_DIR = "/home/node/.openclaw/workspace";

function needsRewriteWorkspace(v) {
  if (!v) return true;
  const s = String(v).trim();
  if (!s) return true;
  // Common non-writable locations on Railway containers
  if (s.startsWith("/data/")) return true;
  if (s.startsWith("/root/")) return true;
  return false;
}

if (!process.env.OPENCLAW_STATE_DIR || !String(process.env.OPENCLAW_STATE_DIR).trim()) {
  process.env.OPENCLAW_STATE_DIR = DEFAULT_STATE_DIR;
}

if (needsRewriteWorkspace(process.env.OPENCLAW_WORKSPACE_DIR)) {
  process.env.OPENCLAW_WORKSPACE_DIR = DEFAULT_WORKSPACE_DIR;
}

// Ensure dirs exist (and fail early with a clear error if not writable)
try {
  fs.mkdirSync(process.env.OPENCLAW_STATE_DIR, { recursive: true });
  fs.mkdirSync(process.env.OPENCLAW_WORKSPACE_DIR, { recursive: true });

  // Quick write test to confirm volume/permissions are ok
  const probe = path.join(process.env.OPENCLAW_STATE_DIR, ".write-test");
  fs.writeFileSync(probe, "ok");
  fs.unlinkSync(probe);
} catch (e) {
  console.error("[openclaw.mjs] state/workspace not writable");
  console.error("OPENCLAW_STATE_DIR =", process.env.OPENCLAW_STATE_DIR);
  console.error("OPENCLAW_WORKSPACE_DIR =", process.env.OPENCLAW_WORKSPACE_DIR);
  console.error(e && e.stack ? e.stack : e);
  process.exit(1);
}

await import("./dist/entry.js");
