import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type {
  MonitoringHealth,
  PriorityBand,
  ReadinessStatus,
  TeamMember,
  Finding,
  AnalysisJob,
} from "../data/types";

export const labels = {
  ready: "Ready",
  needs_attention: "Needs attention",
  incomplete_evidence: "Incomplete evidence",
  healthy: "Healthy",
  degraded: "Degraded",
  failed: "Failed",
  inactive: "Inactive",
  urgent: "Urgent",
  high: "High",
  normal: "Normal",
  low: "Low",
  needs_review: "Needs review",
  action_required: "Action required",
  in_remediation: "In remediation",
  accepted: "Accepted",
  resolved: "Resolved",
  in_progress: "In progress",
  blocked: "Blocked",
  complete: "Complete",
  open: "Open",
  draft: "Draft",
  approval_required: "Approval required",
  approved: "Approved",
  self_filed: "Self-filed",
  superseded: "Superseded",
} as const;

export function titleCase(value: string) {
  return labels[value as keyof typeof labels] ?? value.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function formatDate(value?: string, withTime = false) {
  if (!value) return "—";
  const date = new Date(value);
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  }).format(date);
}

export function relativeDate(value?: string) {
  if (!value) return "No deadline";
  const hours = Math.ceil((new Date(value).getTime() - Date.now()) / 3_600_000);
  if (hours < 0) return Math.abs(hours) < 48 ? `${Math.abs(hours)}h overdue` : `${Math.ceil(Math.abs(hours) / 24)}d overdue`;
  if (hours === 0) return "Due now";
  if (hours < 48) return `Due in ${hours}h`;
  const days = Math.ceil(hours / 24);
  return `Due in ${days}d`;
}

export function memberName(members: TeamMember[], id?: string) {
  return members.find((member) => member.id === id)?.name ?? "Unassigned";
}

export function StatusPill({ value, label }: { value: ReadinessStatus | MonitoringHealth | PriorityBand | string; label?: string }) {
  return <span className={`status-pill status-${value}`}>{label ?? titleCase(value)}</span>;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        {description ? <p className="page-description">{description}</p> : null}
      </div>
      {actions ? <div className="page-header-actions">{actions}</div> : null}
    </header>
  );
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-icon" aria-hidden="true">○</div>
      <h3>{title}</h3>
      <p>{body}</p>
      {action}
    </div>
  );
}

export function MetricCard({ label, value, detail, tone = "neutral", to }: { label: string; value: ReactNode; detail: string; tone?: string; to?: string }) {
  const content = <><p>{label}</p><strong>{value}</strong><span>{detail}</span></>;
  return to ? <Link className={`metric-card metric-card-link tone-${tone}`} to={to}>{content}</Link> : <article className={`metric-card tone-${tone}`}>{content}</article>;
}

export function FindingInsights({ findings, analyses }: { findings: Finding[]; analyses: AnalysisJob[] }) {
  const distribution = (["critical", "high", "medium", "low"] as const).map((severity) => ({ severity, count: findings.filter((item) => item.severity === severity).length }));
  const history = analyses.filter((item) => item.status === "completed" && item.result).sort((a, b) => a.createdAt.localeCompare(b.createdAt)).slice(-6);
  if (findings.length < 3 && history.length < 2) return null;
  const maximum = Math.max(1, ...distribution.map((item) => item.count), ...history.map((item) => (item.result?.newFindings ?? 0) + (item.result?.changedFindings ?? 0)));
  return <section className="panel wide"><SectionHeader title="Finding insights" description="Shown only when enough release evidence exists for a useful comparison."/><div className="insights-grid">{findings.length >= 3 ? <div><h3>Current distribution</h3><ul className="bar-list">{distribution.map((item)=><li key={item.severity}><span>{titleCase(item.severity)}</span><i><b style={{width:`${item.count/maximum*100}%`}}/></i><strong>{item.count}</strong></li>)}</ul></div>:null}{history.length >= 2 ? <div><h3>Analysis history</h3><ul className="bar-list">{history.map((item)=>{const count=(item.result?.newFindings??0)+(item.result?.changedFindings??0);return <li key={item.id}><span>{formatDate(item.createdAt)}</span><i><b style={{width:`${count/maximum*100}%`}}/></i><strong>{count}</strong></li>})}</ul><small>New or changed findings per immutable snapshot</small></div>:null}</div></section>;
}

export function ScopeLink({ productId, releaseId, children }: { productId: string; releaseId?: string; children: ReactNode }) {
  const to = releaseId ? `/products/${productId}/releases/${releaseId}` : `/products/${productId}`;
  return <Link to={to}>{children}</Link>;
}

export function Breadcrumbs({ items }: { items: { label: string; to?: string }[] }) {
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      {items.map((item, index) => (
        <span key={`${item.label}-${index}`}>
          {index > 0 ? <span aria-hidden="true">/</span> : null}
          {item.to ? <Link to={item.to}>{item.label}</Link> : <span aria-current="page">{item.label}</span>}
        </span>
      ))}
    </nav>
  );
}

export function SectionHeader({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="section-header">
      <div>
        <h2>{title}</h2>
        {description ? <p>{description}</p> : null}
      </div>
      {action}
    </div>
  );
}

export function EvidenceMeter({ value, total }: { value: number; total: number }) {
  const percent = total ? Math.round((value / total) * 100) : 0;
  return (
    <div className="meter-wrap" aria-label={`${value} of ${total}`}>
      <div className="meter"><span style={{ width: `${percent}%` }} /></div>
      <span>{value}/{total}</span>
    </div>
  );
}
