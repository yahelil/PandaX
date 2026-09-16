import { describe, expect, it } from "vitest";
import { analysisInputAccept, analysisInputHint, validateSbomFormatVersion } from "./analysisInput";

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

describe("SBOM upload guidance", () => {
  it.each(["1.2", "1.6"])("accepts CycloneDX %s without a version field in the form", async (version) => {
    await expect(validateSbomFormatVersion(new Blob([JSON.stringify({ bomFormat: "CycloneDX", specVersion: version })]))).resolves.toBeUndefined();
  });

  it.each(["SPDX-2.2", "SPDX-2.3"])("accepts %s", async (version) => {
    await expect(validateSbomFormatVersion(new Blob([JSON.stringify({ spdxVersion: version })]))).resolves.toBeUndefined();
  });

  it("rejects a custom version with a clear supported-version message", async () => {
    await expect(validateSbomFormatVersion(new Blob([JSON.stringify({ bomFormat: "CycloneDX", specVersion: "custom" })]))).rejects.toThrow("CycloneDX JSON 1.2 or 1.6");
    expect(analysisInputHint("sbom")).toContain("SPDX 2.2 or 2.3");
  });
});
