#!/usr/bin/env -S deno run -A
//! Bump the version numbers in the repo.

const BUMPS = [
  {
    file: "Cargo.toml",
    pattern: /^version\s*=\s*"(\d+\.\d+\.\d+)"/gm,
    replace: (version: string) => `version = "${version}"`,
  },
  {
    file: "helm/tlb-controller/Chart.yaml",
    pattern: /^version:\s*"(\d+\.\d+\.\d+)"/gm,
    replace: (version: string) => `version: "${version}"`,
  },
  {
    file: "helm/tlb-controller/Chart.yaml",
    pattern: /^appVersion:\s*"(\d+\.\d+\.\d+)"/gm,
    replace: (version: string) => `appVersion: "${version}"`,
  },
  {
    file: "helm/tlb-controller/values.yaml",
    pattern: /tag:\s*"(\d+\.\d+\.\d+)"/,
    replace: (version: string) => `tag: "${version}"`,
  },
];

const version = Deno.args[0];
if (!version) {
  console.error("Please provide a version number as the first argument.");
  Deno.exit(1);
}

let ok = true;
for (const bump of BUMPS) {
  let found = false;
  const content = await Deno.readTextFile(bump.file);
  const newContent = content.replace(bump.pattern, () => {
    found = true;
    return bump.replace(version);
  });
  if (!found) {
    console.warn(`No changes made to ${bump.file}. Pattern not found.`);
    ok = false;
    continue;
  }
  await Deno.writeTextFile(bump.file, newContent);
  console.log(`Updated ${bump.file} to version ${version}`);
}

if (!ok) {
  console.error(
    "Some files were not updated. Please check the warnings above.",
  );
  Deno.exit(1);
}

await new Deno.Command("cargo", { args: ["update"] }).spawn().output();
await new Deno.Command("git", { args: ["add", ...BUMPS.map((b) => b.file), "Cargo.lock"] }).spawn().output();
await new Deno.Command("git", { args: ["commit", "-m", `Release ${version}`] }).spawn().output();
await new Deno.Command("git", { args: ["tag", `v${version}`] }).spawn().output();
console.log(`Version bumped to ${version} and changes committed.`);
