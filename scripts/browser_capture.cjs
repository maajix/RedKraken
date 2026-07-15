#!/usr/bin/env node
/* Authenticated, proxy-enforced Playwright evidence capture. */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { chromium } = require("playwright");

function fail(message) {
  process.stderr.write(`browser_capture: ${message}\n`);
  process.exit(2);
}

function args(argv) {
  const result = { storageState: "", proxy: "", waitMs: 1500, ignoreHTTPSErrors: false };
  const positional = [];
  for (let i = 2; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === "--storage-state") result.storageState = argv[++i] || "";
    else if (value === "--proxy") result.proxy = argv[++i] || "";
    else if (value === "--wait-ms") result.waitMs = Number(argv[++i]);
    else if (value === "--ignore-https-errors") result.ignoreHTTPSErrors = true;
    else positional.push(value);
  }
  [result.engagement, result.url, result.role] = positional;
  return result;
}

function hashFile(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function safeUrl(value) {
  try {
    const parsed = new URL(value);
    const query = parsed.search ? crypto.createHash("sha256").update(parsed.search.slice(1)).digest("hex") : "";
    return `${parsed.origin}${parsed.pathname}${query ? `?sha256=${query}` : ""}`;
  } catch (_) {
    return "<invalid-url>";
  }
}

async function main() {
  const options = args(process.argv);
  if (!options.engagement || !options.url || !options.role) {
    fail("usage: browser_capture.cjs <engagement> <url> <role> --proxy http://127.0.0.1:18080 [--storage-state file] [--wait-ms N] [--ignore-https-errors]");
  }
  if (!options.proxy) fail("--proxy is required; start scripts/start_scope_proxy.sh first");
  if (!/^[A-Za-z0-9._-]+$/.test(options.role)) fail("role must be a short slug");
  if (!Number.isFinite(options.waitMs) || options.waitMs < 0 || options.waitMs > 30000) fail("--wait-ms must be between 0 and 30000");

  const root = path.resolve(__dirname, "..");
  const engagement = path.resolve(options.engagement);
  if (options.storageState) {
    const statePath = path.resolve(options.storageState);
    if (statePath !== engagement && !statePath.startsWith(`${engagement}${path.sep}`)) {
      fail("--storage-state must be inside the active engagement directory");
    }
  }
  const scope = spawnSync("bash", [path.join(root, "lib/scope_check.sh"), options.url, engagement], { encoding: "utf8" });
  if (scope.status !== 0) fail(scope.stdout.trim() || scope.stderr.trim() || "URL is out of scope");

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const output = path.join(engagement, "evidence", "browser", `${stamp}-${options.role}`);
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  fs.chmodSync(output, 0o700);
  const har = path.join(output, "network.har");
  const trace = path.join(output, "trace.zip");
  const screenshot = path.join(output, "page.png");
  const storage = path.join(output, "storage-state.json");
  const events = [];
  let droppedEvents = 0;
  const record = (event) => {
    if (events.length < 50000) events.push(event);
    else droppedEvents += 1;
  };
  const startedAt = new Date().toISOString();

  const browser = await chromium.launch({ headless: true, proxy: { server: options.proxy } });
  try {
    const contextOptions = {
      ignoreHTTPSErrors: options.ignoreHTTPSErrors,
      recordHar: { path: har, content: "embed", mode: "full" },
    };
    if (options.storageState) contextOptions.storageState = path.resolve(options.storageState);
    const context = await browser.newContext(contextOptions);
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    const page = await context.newPage();
    page.on("console", (message) => record({ type: "console", level: message.type(), text: message.text().slice(0, 2000) }));
    page.on("pageerror", (error) => record({ type: "pageerror", text: String(error).slice(0, 2000) }));
    page.on("request", (request) => record({ type: "request", method: request.method(), resource: request.resourceType(), url: safeUrl(request.url()) }));
    page.on("response", (response) => record({ type: "response", status: response.status(), url: safeUrl(response.url()) }));
    page.on("websocket", (socket) => {
      record({ type: "websocket", event: "open", url: safeUrl(socket.url()) });
      socket.on("framesent", (event) => record({ type: "websocket", event: "sent", size: String(event.payload || "").length }));
      socket.on("framereceived", (event) => record({ type: "websocket", event: "received", size: String(event.payload || "").length }));
      socket.on("close", () => record({ type: "websocket", event: "close", url: safeUrl(socket.url()) }));
    });
    const response = await page.goto(options.url, { waitUntil: "domcontentloaded", timeout: 30000 });
    if (options.waitMs) await page.waitForTimeout(options.waitMs);
    await page.screenshot({ path: screenshot, fullPage: true });
    const finalUrl = safeUrl(page.url());
    await context.storageState({ path: storage });
    fs.chmodSync(storage, 0o600);
    await context.tracing.stop({ path: trace });
    await context.close();

    const manifest = {
      schema_version: 1,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      role: options.role,
      requested_url: safeUrl(options.url),
      final_url: finalUrl,
      initial_status: response ? response.status() : null,
      proxy: options.proxy,
      event_count: events.length,
      dropped_event_count: droppedEvents,
      events,
      artifacts: {},
    };
    for (const file of [har, trace, screenshot, storage]) {
      if (fs.existsSync(file)) manifest.artifacts[path.basename(file)] = `sha256:${hashFile(file)}`;
    }
    const manifestPath = path.join(output, "manifest.json");
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    process.stdout.write(`${output}\n`);
  } finally {
    await browser.close();
  }
}

main().catch((error) => fail(error && error.stack ? error.stack : String(error)));
