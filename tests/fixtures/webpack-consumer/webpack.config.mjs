import path from "node:path";
import { fileURLToPath } from "node:url";

const thisFile = fileURLToPath(import.meta.url);
const thisDir = path.dirname(thisFile);

export default {
  mode: "production",
  target: ["web", "es2020"],
  entry: path.resolve(thisDir, "src/index.js"),
  output: {
    filename: "bundle.js",
    path: path.resolve(thisDir, "dist"),
    clean: true,
  },
  performance: {
    hints: false,
  },
};
