import { useAuth } from "./AuthProvider";
import type { AuthRole } from "./oidcClient";

export type Permission =
  | "manage_portfolio"
  | "run_analysis"
  | "run_monitoring"
  | "decide_findings"
  | "manage_remediation"
  | "approve_documents"
  | "manage_settings";

const ALLOWED: Record<Permission, ReadonlySet<AuthRole>> = {
  manage_portfolio: new Set(["org_admin", "compliance_operator"]),
  run_analysis: new Set(["org_admin", "compliance_operator", "security_reviewer"]),
  run_monitoring: new Set(["org_admin", "compliance_operator", "security_reviewer"]),
  decide_findings: new Set(["org_admin", "security_reviewer"]),
  manage_remediation: new Set(["org_admin", "compliance_operator", "security_reviewer"]),
  approve_documents: new Set(["authorized_approver"]),
  manage_settings: new Set(["org_admin"]),
};

export function hasPermission(roles: readonly AuthRole[], permission: Permission): boolean {
  return roles.some((role) => ALLOWED[permission].has(role));
}

export function usePermission(permission: Permission): boolean {
  const auth = useAuth();
  return auth.mode === "demo" || hasPermission(auth.user?.roles ?? [], permission);
}
