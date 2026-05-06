import fs from "node:fs";
import path from "node:path";

const distDir = path.resolve("dist");

function collectJsFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const resolved = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectJsFiles(resolved));
      continue;
    }
    if (
      resolved.endsWith(".js")
      || resolved.endsWith(".mjs")
      || resolved.endsWith(".ts")
    ) {
      files.push(resolved);
    }
  }
  return files;
}

if (!fs.existsSync(distDir)) {
  throw new Error(`Missing dist directory: ${distDir}`);
}

const indexPath = path.join(distDir, "index.html");
if (!fs.existsSync(indexPath)) {
  throw new Error(`Missing built index.html: ${indexPath}`);
}

const jsAssets = collectJsFiles(distDir);
if (jsAssets.length < 1) {
  throw new Error("Expected at least one JS asset in dist");
}

const requiredMarkers = [
  "browser-native-message-stream-consumer",
  "message_channel_text_roundtrip",
  "message_channel_bytes_roundtrip",
  "message_port_close_rejects_send",
  "message_port_abort_is_sticky",
  "broadcast_channel_delivery",
  "readable_stream_bytes",
  "writable_stream_bytes",
  "capability_denied",
  "degraded_mode_denied",
  "detectBrowserNativeMessagingSupport",
  "createBrowserMessageChannel",
  "createBrowserBroadcastChannel",
  "detectBrowserNativeStreamSupport",
  "createBrowserReadableStream",
  "createBrowserWritableStream",
];

const bundleText = jsAssets
  .map((assetPath) => fs.readFileSync(assetPath, "utf8"))
  .join("\n");

const missingMarkers = requiredMarkers.filter(
  (marker) => !bundleText.includes(marker),
);

if (missingMarkers.length > 0) {
  throw new Error(`Built bundle missing markers: ${missingMarkers.join(", ")}`);
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      jsAssetCount: jsAssets.length,
      fixture: "tests/fixtures/browser-native-message-stream-consumer",
      requiredMarkers,
    },
    null,
    2,
  ),
);
