import { prepareRelease, publishExistingRelease, release, releaseNotes } from "./release.ts";

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
  assert(prepared.get("helm/tlb-controller/Chart.yaml") === 'version: "0.7.0"\nappVersion: "0.7.0"\n');
  assert(prepared.get("helm/tlb-controller/values.yaml") === 'image:\n  tag: "0.7.0"\n');
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
const notes = "## Features\n\n- Configure tunnel routing.";
function response(command: string, args: string[]): string {
  if (args[0] === "symbolic-ref") return "main";
  if (args[0] === "tag" && args[1] === "--merged") return "v0.6.5\nv0.6.4";
  if (command === "codex") {
    return [
      JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: notes } }),
      JSON.stringify({ type: "turn.completed" }),
    ].join("\n");
  }
  if (command === "claude") return JSON.stringify({ subtype: "success", result: notes });
  return "";
}

Deno.test("successful release generates notes before writes and creates GitHub release after atomic push", async () => {
  const commands: string[] = [];
  await release(
    "0.7.0",
    (command, args, input) => {
      commands.push([command, ...args].join(" "));
      if (command === "codex") assert(input!.includes("v0.6.5..HEAD"));
      if (command === "gh" && args[0] === "release") assert(input === notes);
      return Promise.resolve(response(command, args));
    },
    (file) => Promise.resolve(fixture().get(file)!),
    () => {
      assert(commands.some((c) => c.startsWith("codex exec")));
      return Promise.resolve();
    },
  );
  assert(commands.filter((c) => c.startsWith("git push")).length === 1);
  assert(commands.at(-2) === "git push --atomic origin HEAD:refs/heads/main refs/tags/v0.7.0");
  assert(commands.at(-1) === "gh release create v0.7.0 --verify-tag --title v0.7.0 --notes-file -");
  assert(!commands.includes("cargo update"));
});

Deno.test("every subprocess failure prevents subsequent release steps", async () => {
  const baseline: string[] = [];
  await release(
    "0.7.0",
    (command, args) => {
      baseline.push(command);
      return Promise.resolve(response(command, args));
    },
    (file) => Promise.resolve(fixture().get(file)!),
    () => Promise.resolve(),
  );
  for (let failure = 0; failure < baseline.length; failure++) {
    let calls = 0;
    let failed = false;
    try {
      await release(
        "0.7.0",
        (command, args) => {
          if (calls++ === failure) throw new Error("injected failure");
          return Promise.resolve(response(command, args));
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

Deno.test("existing tag publication uses its committed range without changing or pushing files", async () => {
  const commands: string[] = [];
  await publishExistingRelease("0.7.0", "claude", (command, args, input) => {
    commands.push([command, ...args].join(" "));
    if (args[0] === "tag") return Promise.resolve("v0.7.0\nv0.6.5");
    if (command === "claude") assert(input!.includes("v0.6.5..refs/tags/v0.7.0"));
    return Promise.resolve(response(command, args));
  });
  assert(!commands.some((c) => /^git (push|commit|add|tag v)/.test(c)));
  assert(commands.at(-1)!.startsWith("gh release create v0.7.0 --verify-tag"));
});

Deno.test("first release includes full history", async () => {
  await releaseNotes("v0.1.0", "HEAD", "codex", (command, args, input) => {
    if (args[0] === "tag") return Promise.resolve("");
    if (command === "codex") {
      assert(input!.includes("initial release"));
      assert(input!.includes("Commit range: HEAD"));
    }
    return Promise.resolve(response(command, args));
  });
});

Deno.test("failed, malformed, or empty AI output prevents file changes and publication", async () => {
  for (
    const [agent, output] of [
      ["codex", ""],
      ["codex", "not JSON"],
      ["codex", '{"type":"turn.failed"}'],
      ["codex", '{"type":"turn.completed"}'],
      ["claude", '{"subtype":"success","is_error":true,"result":"Not logged in"}'],
      ["claude", '{"subtype":"error_max_turns","result":"Partial notes"}'],
      ["claude", '{"subtype":"success","result":"  "}'],
    ] as const
  ) {
    let writes = 0;
    let published = false;
    let failed = false;
    try {
      await release(
        "0.7.0",
        (command, args) => {
          if (command === "gh" && args[0] === "release") published = true;
          return Promise.resolve(command === agent ? output : response(command, args));
        },
        (file) => Promise.resolve(fixture().get(file)!),
        () => {
          writes++;
          return Promise.resolve();
        },
        agent,
      );
    } catch {
      failed = true;
    }
    assert(failed && writes === 0 && !published);
  }
});
