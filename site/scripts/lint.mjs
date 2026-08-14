import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
assert.deepEqual(packageJson.dependencies, {});
assert.deepEqual(packageJson.devDependencies, {});
const build = await readFile(new URL("./build.mjs", import.meta.url), "utf8");
assert.doesNotMatch(build, /fetch\s*\(/);
