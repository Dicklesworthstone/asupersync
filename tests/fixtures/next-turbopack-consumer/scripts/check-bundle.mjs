import fs from "node:fs";
import path from "node:path";

const repo = process.cwd();
const nextDir = path.join(repo, ".next");
const buildIdPath = path.join(nextDir, "BUILD_ID");
const serverDir = path.join(nextDir, "server");

if (!fs.existsSync(nextDir)) {
  throw new Error(`missing .next output directory: ${nextDir}`);
}

if (!fs.existsSync(buildIdPath)) {
  throw new Error(`missing .next BUILD_ID file: ${buildIdPath}`);
}

if (!fs.existsSync(serverDir)) {
  throw new Error(`missing .next/server directory: ${serverDir}`);
}

function collectJsFiles(rootDir) {
  const results = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }
      if (entry.isFile() && fullPath.endsWith(".js")) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

const jsFiles = collectJsFiles(serverDir);
if (jsFiles.length === 0) {
  throw new Error("missing compiled .js server artifacts under .next/server");
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      nextDir,
      buildIdPath,
      serverJsFiles: jsFiles.length,
    },
    null,
    2,
  ),
);
