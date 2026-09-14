import { assembleInstallation } from "./manifests.ts";
import { prepareRelease } from "./release.ts";

Deno.test("release preserves deterministic installation assembly", () => {
  const controller = '---\nkind: Deployment\nimage: "ghcr.io/niklasrosenstein/tlb:0.7.0"\n';
  const crds = "---\nkind: CustomResourceDefinition\n";
  const result = prepareRelease(
    new Map([
      ["Cargo.toml", 'version = "0.7.0"\n'],
      ["Cargo.lock", '[[package]]\nname = "tlb"\nversion = "0.7.0"\n'],
      ["deploy/controller.yaml", controller],
      ["deploy/tlb.yaml", assembleInstallation(crds, controller)],
    ]),
    "0.8.0",
  );
  if (assembleInstallation(crds, result.get("deploy/controller.yaml")!) !== result.get("deploy/tlb.yaml")) {
    throw new Error("Release produced inconsistent manifests");
  }
});
