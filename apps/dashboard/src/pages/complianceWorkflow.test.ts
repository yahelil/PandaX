import { describe, expect, it } from "vitest";

import type { ComplianceItem, Role } from "../data/types";
import {
  allowedComplianceStatuses,
  compareCompliance,
  compliancePermissions,
  isComplianceResolved,
  lifecycleStatus,
} from "./complianceWorkflow";

const item = (patch: Partial<ComplianceItem> = {}): ComplianceItem => ({
  id: "item-1",
  type: "reporting_case",
  title: "72-hour notification",
  requirement: "CRA Article 14",
  priority: "urgent",
  status: "open",
  reason: "A report is required.",
  targetUrl: "/compliance?item=item-1",
  ...patch,
});

describe("compliance lifecycle", () => {
  it("keeps acknowledged work distinct from resolved work", () => {
    const acknowledged = item({ lifecycleStatus: "acknowledged", status: "in_progress" });
    expect(lifecycleStatus(acknowledged)).toBe("acknowledged");
    expect(isComplianceResolved(acknowledged)).toBe(false);
  });

  it("requires reporting cases to be acknowledged before resolution", () => {
    expect(allowedComplianceStatuses(item({ lifecycleStatus: "approved" }))).toEqual(["approved", "acknowledged"]);
    expect(allowedComplianceStatuses(item({ lifecycleStatus: "acknowledged" }))).toEqual(["acknowledged", "resolved"]);
  });

  it.each([
    [["compliance_operator"], "pending_approval", { canEdit: true, canApprove: false }],
    [["authorized_approver"], "pending_approval", { canEdit: false, canApprove: true }],
    [["org_admin"], "pending_approval", { canEdit: true, canApprove: true }],
    [["viewer"], "action_required", { canEdit: false, canApprove: false }],
  ] as Array<[Role[], ComplianceItem["lifecycleStatus"], ReturnType<typeof compliancePermissions>]>) (
    "applies backend roles for %j",
    (roles, status, expected) => expect(compliancePermissions(roles, item({ lifecycleStatus: status }))).toEqual(expected),
  );

  it("supports organization-level work without inventing a product", () => {
    expect(item().productId).toBeUndefined();
  });

  it("keeps obligations without deadlines last in both sort directions", () => {
    const undated = item({ id: "undated" });
    const dated = item({ id: "dated", dueAt: "2026-09-15T08:00:00Z" });
    expect(compareCompliance(undated, dated, "due", "asc")).toBeGreaterThan(0);
    expect(compareCompliance(undated, dated, "due", "desc")).toBeGreaterThan(0);
  });
});
