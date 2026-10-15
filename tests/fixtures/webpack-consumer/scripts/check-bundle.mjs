import fs from "node:fs";
import path from "node:path";

const repo = process.cwd();
const distDir = path.join(repo, "dist");
const bundlePath = path.join(distDir, "bundle.js");

if (!fs.existsSync(distDir)) {
  throw new Error(`missing dist directory: ${distDir}`);
}

if (!fs.existsSync(bundlePath)) {
  throw new Error(`missing webpack bundle: ${bundlePath}`);
}

const size = fs.statSync(bundlePath).size;
if (size <= 0) {
  throw new Error(`webpack bundle is empty: ${bundlePath}`);
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      bundlePath,
      bytes: size,
    },
    null,
    2,
  ),
);
