import { describe, expect, it } from "vitest";

import { analysisInputAccept, analysisInputHint } from "./analysisInput";

describe("analysis input selection", () => {
  it("offers every raw artifact type accepted by the production API", () => {
    const accepted = analysisInputAccept("raw_artifact").split(",");
    expect(accepted).toEqual(expect.arrayContaining([".zip", ".tar", ".tar.gz", ".tgz", ".bin", ".img"]));
    expect(analysisInputHint("raw_artifact")).toContain("BIN");
  });

  it("keeps Collector and SBOM choices narrowly scoped", () => {
    expect(analysisInputAccept("collector_package")).toBe(".zip,application/zip,application/x-zip-compressed");
    expect(analysisInputAccept("sbom")).not.toContain(".bin");
  });
});
