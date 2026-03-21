import fs from "node:fs";
import path from "node:path";

const distDir = path.resolve("dist");
const indexPath = path.join(distDir, "index.html");
const assetDir = path.join(distDir, "assets");

if (!fs.existsSync(distDir)) {
  throw new Error(`Missing dist directory: ${distDir}`);
}

if (!fs.existsSync(indexPath)) {
  throw new Error(`Missing built index.html: ${indexPath}`);
}

if (!fs.existsSync(assetDir)) {
  throw new Error(`Missing assets directory: ${assetDir}`);
}

const assets = fs.readdirSync(assetDir);
const jsAssets = assets.filter((name) => name.endsWith(".js") || name.endsWith(".mjs"));
const wasmAssets = assets.filter((name) => name.endsWith(".wasm"));
const jsContents = jsAssets.map((name) =>
  fs.readFileSync(path.join(assetDir, name), "utf8"),
);

if (jsAssets.length < 2) {
  throw new Error("Expected at least two JavaScript assets in dist/assets for main-thread + worker bundles");
}

if (wasmAssets.length === 0) {
  throw new Error("Expected at least one wasm asset in dist/assets");
}

const indexHtml = fs.readFileSync(indexPath, "utf8");
if (!/(?:^|["'(])(?:\.\/)?assets\//.test(indexHtml)) {
  throw new Error("Built index.html does not reference hashed assets");
}

if (!jsContents.some((content) => content.includes("rust-browser-worker-ready"))) {
  throw new Error("Built assets must retain the dedicated worker ready marker");
}

if (!jsContents.some((content) => content.includes("rust-browser-downgrade-missing-webassembly"))) {
  throw new Error("Built assets must retain the downgrade simulation marker");
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      jsAssetCount: jsAssets.length,
      wasmAssetCount: wasmAssets.length,
      workerBundleMarkerPresent: jsContents.some((content) =>
        content.includes("rust-browser-worker-ready"),
      ),
      downgradeMarkerPresent: jsContents.some((content) =>
        content.includes("rust-browser-downgrade-missing-webassembly"),
      ),
    },
    null,
    2,
  ),
);
