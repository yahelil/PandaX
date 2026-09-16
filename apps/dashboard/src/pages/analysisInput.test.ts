import { describe, expect, it } from "vitest";

import { analysisInputAccept, analysisInputHint } from "./analysisInput";

describe("analysis input selection", () => {
  it("offers hosted archive formats without firmware images", () => {
    const accepted = analysisInputAccept("raw_artifact").split(",");
    expect(accepted).toEqual(expect.arrayContaining([".zip", ".tar", ".tar.gz", ".tgz"]));
    expect(accepted).not.toContain(".bin");
    expect(accepted).not.toContain(".img");
  });

  it("keeps Collector and SBOM choices narrowly scoped", () => {
    expect(analysisInputAccept("collector_package")).toBe(".zip,application/zip,application/x-zip-compressed");
    expect(analysisInputAccept("sbom")).not.toContain(".bin");
  });
});
