import { describe, expect, it, vi } from "vitest";

import { FixtureAdapter } from "./fixtureAdapter";
import { createDemoState } from "./fixtures";
import type { ComplianceDto, GovernanceApi } from "./governanceApi";
import type { PortfolioApi } from "./portfolioApi";
import { ProductionAdapter } from "./productionAdapter";

const base: ComplianceDto = {
  id: "organization-case",
  organizationId: "org-acme",
  kind: "reporting_case",
  title: "Coordinate organization-wide incident report",
  description: "Legal and security review must complete before filing.",
  priority: "critical",
  status: "pending_approval",
  readiness: "review_required",
  dueAt: "2026-09-15T08:00:00Z",
  ownerId: "member-jane",
  sourceType: "case_store",
  sourceId: "case-org-1",
  reportingStage: "notification",
  version: 4,
  createdAt: "2026-09-14T08:00:00Z",
  updatedAt: "2026-09-14T09:00:00Z",
};

function adapter(governance: Partial<GovernanceApi>) {
  return new ProductionAdapter({
    organizationId: "org-acme",
    portfolioApi: {} as PortfolioApi,
    governanceApi: governance as GovernanceApi,
    fixtureAdapter: new FixtureAdapter(createDemoState(), false),
  });
}

describe("production compliance adapter", () => {
  it("loads organization-level detail and audit without inventing product scope", async () => {
    const getCompliance = vi.fn(async () => base);
    const listComplianceAudit = vi.fn(async () => [{
      id: "audit-1", organizationId: "org-acme", itemId: base.id, action: "compliance.created",
      actorId: "projector", itemVersion: 0, occurredAt: base.createdAt, payload: {},
    }]);
    const result = await adapter({ getCompliance, listComplianceAudit }).loadComplianceDetail(base.id);

    expect(result).toMatchObject({ id: base.id, productId: undefined, lifecycleStatus: "pending_approval" });
    expect(result?.audit).toHaveLength(1);
  });

  it("uses optimistic versions for updates and independent approval", async () => {
    const updateCompliance = vi.fn(async (_organization, _item, input) => ({ ...base, title: input.title ?? base.title, version: 5 }));
    const approveCompliance = vi.fn(async () => ({ ...base, status: "approved" as const, approvedBy: "approver-1", approvedAt: "2026-09-14T10:00:00Z", version: 5 }));
    const governance = {
      getCompliance: vi.fn(async () => base),
      listComplianceAudit: vi.fn(async () => []),
      updateCompliance,
      approveCompliance,
    };

    const updateAdapter = adapter(governance);
    await updateAdapter.loadComplianceDetail(base.id);
    await updateAdapter.updateCompliance({ itemId: base.id, title: "Updated notification" });
    expect(updateCompliance).toHaveBeenCalledWith("org-acme", base.id, expect.objectContaining({ expectedVersion: 4, title: "Updated notification" }));

    const approvalAdapter = adapter(governance);
    await approvalAdapter.loadComplianceDetail(base.id);
    const approved = await approvalAdapter.approveCompliance({ itemId: base.id });
    expect(approveCompliance).toHaveBeenCalledWith("org-acme", base.id, { expectedVersion: 4, selfFilingRecordId: undefined, selfFilingRecordUrl: undefined });
    expect(approved).toMatchObject({ lifecycleStatus: "approved", approvedBy: "approver-1" });
  });
});
