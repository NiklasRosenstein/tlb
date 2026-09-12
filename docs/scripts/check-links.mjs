import { readdir, readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve("dist");
const origin = "https://niklasrosenstein.github.io";
const base = "/tlb";
const html = new Map();
async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await collect(path);
    else if (entry.name.endsWith(".html")) html.set(path, await readFile(path, "utf8"));
  }
}
await collect(root);
const failures = [];
for (const [file, content] of html) {
  const relative = file.slice(root.length).replace(/\/index\.html$/, "/");
  const current = new URL(base + relative, origin);
  for (const [, raw] of content.matchAll(/\bhref=["']([^"']*)["']/g)) {
    const href = raw.replaceAll("&amp;", "&");
    if (/^(mailto:|tel:|javascript:|data:)/.test(href)) continue;
    const url = new URL(href, current);
    if (url.origin !== origin) continue;
    if (!(url.pathname === base || url.pathname.startsWith(base + "/"))) {
      failures.push(`${file}: link escapes the Pages base: ${href}`);
      continue;
    }
    // Astro's error document is 404.html; its canonical URL follows trailingSlash.
    if (file === join(root, "404.html") && url.pathname === base + "/404/") continue;
    let target = resolve(root, "." + decodeURIComponent(url.pathname.slice(base.length)));
    try {
      if ((await stat(target)).isDirectory()) target = join(target, "index.html");
      await stat(target);
      if (url.hash && target.endsWith(".html")) {
        const text = html.get(target) ?? await readFile(target, "utf8");
        const id = decodeURIComponent(url.hash.slice(1));
        const ids = new Set([...text.matchAll(/\bid=["']([^"']*)["']/g)].map((m) => m[1]));
        if (!ids.has(id)) failures.push(`${file}: missing anchor ${href}`);
      }
    } catch {
      failures.push(`${file}: missing target ${href}`);
    }
  }
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`Checked local links and anchors across ${html.size} HTML pages under ${base}/.`);
