import fs from "node:fs";
import path from "node:path";

const distDir = path.resolve("dist");
const indexPath = path.join(distDir, "index.html");

if (!fs.existsSync(distDir)) {
  throw new Error(`Missing dist directory: ${distDir}`);
}

if (!fs.existsSync(indexPath)) {
  throw new Error(`Missing built index.html: ${indexPath}`);
}

const assetDir = path.join(distDir, "assets");
if (!fs.existsSync(assetDir)) {
  throw new Error(`Missing assets directory: ${assetDir}`);
}

const jsAssets = fs
  .readdirSync(assetDir)
  .filter((name) => name.endsWith(".js") || name.endsWith(".mjs"));
if (jsAssets.length === 0) {
  throw new Error("Expected at least one JS asset in dist/assets");
}

const indexHtml = fs.readFileSync(indexPath, "utf8");
if (!indexHtml.includes('<script type="module"')) {
  throw new Error("Built index.html must include a module script tag");
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      jsAssetCount: jsAssets.length,
      assetDir,
    },
    null,
    2,
  ),
);
