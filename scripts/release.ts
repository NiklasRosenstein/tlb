#!/usr/bin/env -S deno run -A
//! Validate, commit and atomically publish a versioned release.

export const RELEASE_FILES = [
  "Cargo.toml",
  "Cargo.lock",
  "helm/tlb-controller/Chart.yaml",
  "helm/tlb-controller/values.yaml",
];

export function prepareRelease(files: Map<string, string>, version: string): Map<string, string> {
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) {
    throw new Error("Version must be a canonical major.minor.patch number");
  }
  const result = new Map(files);
  let current: string | undefined;
  const replace = (file: string, pattern: RegExp, format: (match: RegExpMatchArray) => string) => {
    const content = result.get(file);
    if (content === undefined) throw new Error(`Missing ${file}`);
    const matches = [...content.matchAll(pattern)];
    if (matches.length !== 1) throw new Error(`Expected exactly one version field in ${file}`);
    const match = matches[0];
    const previous = match[1];
    current ??= previous;
    if (previous !== current) throw new Error(`Inconsistent release version in ${file}`);
    if (previous === version) throw new Error(`Version is already ${version}`);
    result.set(file, content.slice(0, match.index) + format(match) + content.slice(match.index! + match[0].length));
  };
  replace("Cargo.toml", /^version\s*=\s*"(\d+\.\d+\.\d+)"/gm, () => `version = "${version}"`);
  replace(
    "Cargo.lock",
    /\[\[package\]\]\nname = "tlb"\nversion = "(\d+\.\d+\.\d+)"/g,
    () => `[[package]]\nname = "tlb"\nversion = "${version}"`,
  );
  replace("helm/tlb-controller/Chart.yaml", /^version:\s*"(\d+\.\d+\.\d+)"/gm, () => `version: "${version}"`);
  replace("helm/tlb-controller/Chart.yaml", /^appVersion:\s*"(\d+\.\d+\.\d+)"/gm, () => `appVersion: "${version}"`);
  replace("helm/tlb-controller/values.yaml", /tag:\s*"(\d+\.\d+\.\d+)"/g, () => `tag: "${version}"`);
  return result;
}

export type Runner = (command: string, args: string[]) => Promise<string>;

async function checked(command: string, args: string[]): Promise<string> {
  const child = new Deno.Command(command, { args, stdout: "piped", stderr: "inherit" }).spawn();
  const timer = setTimeout(() => {
    try {
      child.kill("SIGKILL");
    } catch { /* Process has already exited. */ }
  }, 120_000);
  try {
    const output = await child.output();
    if (!output.success) throw new Error(`${command} ${args.join(" ")} failed with exit ${output.code}`);
    return new TextDecoder().decode(output.stdout).trim();
  } finally {
    clearTimeout(timer);
  }
}

export async function release(
  version: string,
  run: Runner = checked,
  read: (file: string) => Promise<string> = Deno.readTextFile,
  write: (file: string, text: string) => Promise<void> = Deno.writeTextFile,
): Promise<void> {
  if (await run("git", ["status", "--porcelain"])) throw new Error("Release requires a clean working tree");
  const branch = await run("git", ["symbolic-ref", "--short", "HEAD"]);
  if (!branch) throw new Error("Release requires a branch");
  if (await run("git", ["tag", "--list", `v${version}`])) throw new Error("Release tag already exists");
  const files = new Map(await Promise.all(RELEASE_FILES.map(async (file) => [file, await read(file)] as const)));
  const prepared = prepareRelease(files, version);
  for (const [file, text] of prepared) await write(file, text);
  await run("cargo", ["check", "--locked", "--all-targets", "--all-features"]);
  await run("git", ["add", "--", ...RELEASE_FILES]);
  await run("git", ["commit", "-m", `Release ${version}`]);
  await run("git", ["tag", `v${version}`]);
  await run("git", ["push", "--atomic", "origin", `HEAD:refs/heads/${branch}`, `refs/tags/v${version}`]);
}

if (import.meta.main) {
  if (Deno.args.length !== 1) throw new Error("Usage: release.ts major.minor.patch");
  await release(Deno.args[0]);
  console.log(`Published v${Deno.args[0]}`);
}
