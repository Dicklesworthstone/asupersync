import fs from "node:fs";
import path from "node:path";

const repo = process.cwd();
const distDir = path.join(repo, "dist");
const indexHtml = path.join(distDir, "index.html");
const assetsDir = path.join(distDir, "assets");

if (!fs.existsSync(indexHtml)) {
  throw new Error(`missing built index.html: ${indexHtml}`);
}

if (!fs.existsSync(assetsDir)) {
  throw new Error(`missing built assets directory: ${assetsDir}`);
}

const assetEntries = fs.readdirSync(assetsDir).filter((entry) => entry.endsWith(".js"));
if (assetEntries.length === 0) {
  throw new Error("missing built JavaScript asset in dist/assets");
}

const indexHtmlContent = fs.readFileSync(indexHtml, "utf8");
if (!indexHtmlContent.includes("/assets/")) {
  throw new Error("built index.html does not reference hashed assets");
}

let sawStorageArtifactMarker = false;
let sawStorageNamespaceMarker = false;
let sawArtifactNamespaceMarker = false;
for (const assetEntry of assetEntries) {
  const content = fs.readFileSync(path.join(assetsDir, assetEntry), "utf8");
  sawStorageArtifactMarker ||= content.includes("vanilla-storage-artifact-flow");
  sawStorageNamespaceMarker ||= content.includes("vanilla_fixture_storage");
  sawArtifactNamespaceMarker ||= content.includes("vanilla_fixture_artifacts");
}

if (!sawStorageArtifactMarker) {
  throw new Error("built vanilla bundle must retain the storage/artifact exercise marker");
}

if (!sawStorageNamespaceMarker || !sawArtifactNamespaceMarker) {
  throw new Error("built vanilla bundle must retain the storage and artifact namespace markers");
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      indexHtml,
      jsAssets: assetEntries,
      sawStorageArtifactMarker,
      sawStorageNamespaceMarker,
      sawArtifactNamespaceMarker,
    },
    null,
    2,
  ),
);
