import type {
  ComplianceItem,
  ComplianceLifecycleStatus,
  Role,
} from "../data/types";

const transitions: Record<ComplianceLifecycleStatus, readonly ComplianceLifecycleStatus[]> = {
  action_required: ["in_progress", "pending_approval", "resolved"],
  in_progress: ["action_required", "pending_approval", "resolved"],
  pending_approval: ["action_required", "in_progress"],
  approved: ["acknowledged", "resolved"],
  acknowledged: ["resolved"],
  resolved: [],
};

export function lifecycleStatus(item: ComplianceItem): ComplianceLifecycleStatus {
  if (item.lifecycleStatus) return item.lifecycleStatus;
  if (item.status === "in_progress") return "in_progress";
  if (item.status === "blocked" && item.type === "approval") return "pending_approval";
  if (item.status === "complete") return "resolved";
  return "action_required";
}

export function isComplianceResolved(item: ComplianceItem): boolean {
  return lifecycleStatus(item) === "resolved";
}

export function compliancePermissions(roles: readonly Role[], item: ComplianceItem) {
  const canEdit = roles.some((role) => role === "org_admin" || role === "compliance_operator");
  const canApproveRole = roles.some((role) => role === "org_admin" || role === "authorized_approver");
  return {
    canEdit,
    canApprove: canApproveRole && lifecycleStatus(item) === "pending_approval",
  };
}

export function allowedComplianceStatuses(item: ComplianceItem): ComplianceLifecycleStatus[] {
  const current = lifecycleStatus(item);
  return [current, ...transitions[current]].filter((status) => {
    if (status === "approved" && status !== current) return false;
    if (item.type === "reporting_case" && status === "resolved" && current !== "acknowledged") return false;
    return true;
  });
}

export function compliancePriority(item: ComplianceItem): "critical" | "high" | "medium" | "low" {
  if (item.priority === "urgent") return "critical";
  if (item.priority === "normal") return "medium";
  return item.priority;
}

export function compareCompliance(
  left: ComplianceItem,
  right: ComplianceItem,
  sort: "priority" | "due" | "updated" | "status",
  direction: "asc" | "desc",
): number {
  const priority = { urgent: 0, high: 1, normal: 2, low: 3 };
  const status = { action_required: 0, in_progress: 1, pending_approval: 2, approved: 3, acknowledged: 4, resolved: 5 };
  if (sort === "due" && Boolean(left.dueAt) !== Boolean(right.dueAt)) return left.dueAt ? -1 : 1;
  const values = sort === "priority"
    ? [priority[left.priority], priority[right.priority]]
    : sort === "status"
      ? [status[lifecycleStatus(left)], status[lifecycleStatus(right)]]
      : sort === "updated"
        ? [left.updatedAt ? new Date(left.updatedAt).getTime() : 0, right.updatedAt ? new Date(right.updatedAt).getTime() : 0]
        : [left.dueAt ? new Date(left.dueAt).getTime() : 0, right.dueAt ? new Date(right.dueAt).getTime() : 0];
  const result = values[0] - values[1] || left.title.localeCompare(right.title);
  return direction === "asc" ? result : -result;
}
