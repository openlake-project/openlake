import { chmod, copyFile, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { basename, join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { build } from "esbuild";
import { inject } from "postject";

const exec = promisify(execFile);
const root = process.cwd();
const workDir = resolve(root, ".control-plane");
const outputDir = resolve(root, "dist/bin");
const clientDir = resolve(root, "dist/client");
const serverEntry = resolve(root, "dist/server/index.js");
const bundlePath = join(workDir, "control-plane.cjs");
const blobPath = join(workDir, "control-plane.blob");
const seaConfigPath = join(workDir, "sea-config.json");
const executableName = process.platform === "win32" ? "openlake-control-plane.exe" : "openlake-control-plane";
const executablePath = join(outputDir, executableName);

async function collectFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await collectFiles(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

await readFile(serverEntry);
await rm(workDir, { force: true, recursive: true });
await mkdir(workDir, { recursive: true });
await mkdir(outputDir, { recursive: true });

await build({
  bundle: true,
  entryPoints: [resolve(root, "server/control-plane.mjs")],
  format: "cjs",
  logLevel: "warning",
  outfile: bundlePath,
  platform: "node",
  target: "node24",
});

const assets = {};
for (const file of await collectFiles(clientDir)) {
  assets[relative(clientDir, file).split("\\").join("/")] = relative(workDir, file).split("\\").join("/");
}
await writeFile(seaConfigPath, JSON.stringify({
  assets,
  disableExperimentalSEAWarning: true,
  main: basename(bundlePath),
  output: basename(blobPath),
  useCodeCache: false,
  useSnapshot: false,
}, null, 2));

await exec(process.execPath, ["--experimental-sea-config", basename(seaConfigPath)], { cwd: workDir });
await copyFile(process.execPath, executablePath);
await chmod(executablePath, 0o755);

if (process.platform === "darwin") {
  await exec("/usr/bin/codesign", ["--remove-signature", executablePath]).catch(() => {});
}
await inject(executablePath, "NODE_SEA_BLOB", await readFile(blobPath), {
  machoSegmentName: "NODE_SEA",
  sentinelFuse: "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
});
if (process.platform === "darwin") {
  await exec("/usr/bin/codesign", ["--sign", "-", executablePath]);
}

console.log(`Built ${basename(executablePath)}`);
console.log(executablePath);
