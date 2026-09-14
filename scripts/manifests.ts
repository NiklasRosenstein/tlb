#!/usr/bin/env -S deno run --allow-read --allow-write
//! Assemble the installation bundle from generated CRDs and controller resources.
export function assembleInstallation(crds: string, controller: string): string {
  return `${crds.trim()}\n${controller.trim()}\n`;
}

if (import.meta.main) {
  const expected = assembleInstallation(
    await Deno.readTextFile("deploy/crds.yaml"),
    await Deno.readTextFile("deploy/controller.yaml"),
  );
  if (Deno.args.includes("--check")) {
    if (await Deno.readTextFile("deploy/tlb.yaml") !== expected) {
      throw new Error("Installation bundle is stale; run mise run update-crds");
    }
  } else {
    await Deno.writeTextFile("deploy/tlb.yaml", expected);
  }
}
