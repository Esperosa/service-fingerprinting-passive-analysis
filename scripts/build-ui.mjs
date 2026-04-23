import { build } from "esbuild";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

await mkdir("ui", { recursive: true });

const styleParts = [
  "ui-src/styles/base.css",
  "ui-src/styles/left-rail.css",
  "ui-src/styles/center-stage.css",
  "ui-src/styles/right-panel.css",
  "ui-src/styles/compact.css",
];

const styleEntry = "ui/.styles.entry.pcss";
const styleSource = (await Promise.all(styleParts.map((file) => readFile(file, "utf8")))).join("\n\n");
const tailwindEntry = styleSource;
await writeFile(styleEntry, tailwindEntry, "utf8");

await build({
  entryPoints: ["ui-src/main.ts"],
  outfile: "ui/app.js",
  bundle: true,
  format: "esm",
  target: "es2022",
  sourcemap: false,
  minify: false,
  legalComments: "none",
});

await execFileAsync(
  "node",
  [
    "./node_modules/tailwindcss/lib/cli.js",
    "-c",
    "tailwind.config.cjs",
    "-i",
    styleEntry,
    "-o",
    "ui/styles.css",
    "--minify",
  ],
  { cwd: process.cwd() },
);

const cacheBust = Date.now().toString(36);
const indexHtml = `<!doctype html>
<html lang="cs">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bakula - Bezpecnostni prehled site</title>
  <meta
    name="description"
    content="Bakula dashboard pro topologii, rizika, assety a monitoring s focus-panely bez stránkového scrollu."
  >
  <link rel="stylesheet" href="/styles.css?v=${cacheBust}">
</head>
<body>
  <div id="app"></div>
  <script type="module" src="/app.js?v=${cacheBust}"></script>
</body>
</html>
`;

await writeFile("ui/index.html", indexHtml, "utf8");
