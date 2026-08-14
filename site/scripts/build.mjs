import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";

const source = new URL("../../artifacts/dashboard.html", import.meta.url);
const output = new URL("../dist/", import.meta.url);
const htmlOutput = new URL("../dist/index.html", import.meta.url);
const hostingOutput = new URL("../dist/.openai/hosting.json", import.meta.url);

await rm(output, { recursive: true, force: true });
await mkdir(new URL("../dist/.openai/", import.meta.url), { recursive: true });
let html = await readFile(source, "utf8");
html = html.replace(
  "</head>",
  '<link rel="icon" href="/favicon.svg" type="image/svg+xml"></head>',
);
await writeFile(htmlOutput, html, "utf8");
await cp(new URL("../public/favicon.svg", import.meta.url), new URL("../dist/favicon.svg", import.meta.url));
await cp(new URL("../.openai/hosting.json", import.meta.url), hostingOutput);
