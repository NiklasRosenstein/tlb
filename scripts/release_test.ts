import { prepareRelease, release } from "./release.ts";

function fixture() {
  return new Map([
    ["Cargo.toml", '[package]\nname = "tlb"\nversion = "0.6.5"\n'],
    ["Cargo.lock", '[[package]]\nname = "dep"\nversion = "1.2.3"\n\n[[package]]\nname = "tlb"\nversion = "0.6.5"\n'],
    ["helm/tlb-controller/Chart.yaml", 'version: "0.6.5"\nappVersion: "0.6.5"\n'],
    ["helm/tlb-controller/values.yaml", 'image:\n  tag: "0.6.5"\n'],
  ]);
}
function assert(condition: boolean) {
  if (!condition) throw new Error("Assertion failed");
}
Deno.test("release preserves dependency versions and input files", () => {
  const files = fixture();
  const prepared = prepareRelease(files, "0.7.0");
  assert(prepared.get("Cargo.lock")!.includes('name = "dep"\nversion = "1.2.3"'));
  assert(prepared.get("Cargo.lock")!.includes('name = "tlb"\nversion = "0.7.0"'));
  assert(files.get("Cargo.toml")!.includes('version = "0.6.5"'));
});
Deno.test("invalid, repeated, missing and inconsistent versions fail before writes", async () => {
  for (const version of ["bad", "01.2.3", "0.6.5", "0.7.0"]) {
    const files = fixture();
    if (version === "0.7.0") files.set("helm/tlb-controller/Chart.yaml", 'version: "0.5.0"\n');
    let writes = 0;
    let failed = false;
    try {
      await release(
        version,
        (_command, args) => Promise.resolve(args[0] === "symbolic-ref" ? "main" : ""),
        (file) => Promise.resolve(files.get(file)!),
        () => {
          writes++;
          return Promise.resolve();
        },
      );
    } catch {
      failed = true;
    }
    assert(failed && writes === 0);
  }
});
Deno.test("every subprocess failure prevents subsequent release steps", async () => {
  for (let failure = 0; failure < 8; failure++) {
    let calls = 0;
    let failed = false;
    try {
      await release(
        "0.7.0",
        (_command, args) => {
          if (calls++ === failure) throw new Error("injected failure");
          return Promise.resolve(args[0] === "symbolic-ref" ? "main" : "");
        },
        (file) => Promise.resolve(fixture().get(file)!),
        () => Promise.resolve(),
      );
    } catch {
      failed = true;
    }
    assert(failed && calls === failure + 1);
  }
});
Deno.test("successful release uses one atomic push and no dependency update", async () => {
  const commands: string[] = [];
  await release(
    "0.7.0",
    (command, args) => {
      commands.push([command, ...args].join(" "));
      return Promise.resolve(args[0] === "symbolic-ref" ? "main" : "");
    },
    (file) => Promise.resolve(fixture().get(file)!),
    () => Promise.resolve(),
  );
  assert(commands.filter((c) => c.startsWith("git push")).length === 1);
  assert(commands.at(-1) === "git push --atomic origin HEAD:refs/heads/main refs/tags/v0.7.0");
  assert(!commands.includes("cargo update"));
});
