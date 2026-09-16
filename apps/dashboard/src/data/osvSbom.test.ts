import { afterEach, describe, expect, it, vi } from "vitest";

import { analyzeSbomWithOsv } from "./osvSbom";

afterEach(() => vi.unstubAllGlobals());

describe("uploaded SBOM advisory matching", () => {
  it("turns exact OSV Package URL hits into release findings", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-29mw-wpgm-hmr9" }] }] }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: "GHSA-29mw-wpgm-hmr9",
        aliases: ["CVE-2020-8203"],
        summary: "Prototype pollution in lodash",
        database_specific: { severity: "HIGH" },
      }), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    const file = new Blob([JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.2",
      components: [{ name: "lodash", version: "4.17.19", purl: "pkg:npm/lodash@4.17.19" }],
    })]);

    const result = await analyzeSbomWithOsv(file, "product-juice", "release-11.1.2");

    expect(result).toMatchObject({ components: 1, matchableComponents: 1 });
    expect(result.findings).toEqual([expect.objectContaining({
      reference: "CVE-2020-8203",
      component: "lodash",
      componentVersion: "4.17.19",
      severity: "high",
      productId: "product-juice",
      releaseId: "release-11.1.2",
    })]);
    expect(fetcher).toHaveBeenNthCalledWith(1, "https://api.osv.dev/v1/querybatch", expect.objectContaining({ method: "POST" }));
    expect(fetcher).toHaveBeenNthCalledWith(2, "https://api.osv.dev/v1/vulns/GHSA-29mw-wpgm-hmr9", undefined);
  });
});
