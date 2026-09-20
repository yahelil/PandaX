import { Link, useSearchParams } from "react-router-dom";
import { useDemo } from "../data/DemoProvider";
import { MetricCard, PageHeader, SectionHeader, StatusPill, formatDate, memberName, relativeDate } from "./PageKit";
import "./pages.css";
import { homeSetupMode } from "./homeSetup";
import { matchesScope, scopedPath, scopeFromParams } from "./scope";

export function HomePage() {
  const demo = useDemo();
  const [params] = useSearchParams();
  const scope = scopeFromParams(params);
  const isScoped = Boolean(scope.productId || scope.releaseId);
  const activeActions = demo.actionItems
    .filter((item) => matchesScope(item, scope))
    .filter((item) => item.status !== "completed")
    .sort((a, b) => ({ urgent: 0, high: 1, normal: 2, low: 3 }[a.priority] - { urgent: 0, high: 1, normal: 2, low: 3 }[b.priority]));
  const counters = isScoped ? undefined : demo.state.home?.counters;
  const needsReview = counters?.findingsNeedingAction ?? demo.findings.filter((item) => matchesScope(item, scope) && (item.status === "needs_review" || item.status === "action_required")).length;
  const deadlinesAtRisk = counters ? counters.overdueObligations + counters.dueSoonObligations : activeActions.filter((item) => item.type === "deadline").length;
  const incompleteEvidence = counters?.missingEvidence ?? activeActions.filter((item) => item.type === "evidence").length;
  const scopedReleases = demo.releases.filter((item) => matchesScope(item, scope));
  const scopedProducts = demo.products.filter((item) => !scope.productId || item.id === scope.productId);
  const degraded = scope.releaseId
    ? scopedReleases.filter((item) => item.monitoringHealth === "degraded" || item.monitoringHealth === "failed")
    : scopedProducts.filter((item) => item.monitoringHealth === "degraded" || item.monitoringHealth === "failed");
  const monitoring = isScoped ? undefined : demo.state.home?.monitoring;
  const monitoringNeedsAttention = monitoring ? monitoring.state !== "healthy" : degraded.length > 0;
  const monitoringIssueCount = monitoring ? monitoring.degraded + monitoring.failed + monitoring.stale + monitoring.inactive + monitoring.notConfigured : degraded.length;
  const recentChanges = demo.state.activities.filter((item) => matchesScope(item, scope));
  const hasProduct = demo.products.length > 0;
  const hasRelease = demo.releases.length > 0;
  const hasAnalysis = demo.releases.some((item) => item.lastAnalysisAt) || demo.state.analysisJobs.some((item) => item.status === "completed");
  const hasReview = hasAnalysis && (demo.findings.length === 0 || demo.findings.some((item) => item.decisions.length > 0));
  const hasApprover = demo.state.members.some((item) => item.status === "active" && item.roles.includes("authorized_approver"));
  const notificationsConfigured = Object.entries(demo.state.settings.notifications).some(([key, value]) => key === "emailDigest" ? value !== "off" : value === true);
  const setupMode = homeSetupMode({ isScoped, hasProduct });
  const setupSteps = [
    { label: "Create product", done: hasProduct, to: "/products" },
    { label: "Register release", done: hasRelease, to: hasProduct ? `/products/${demo.products[0].id}?tab=releases` : "/products" },
    { label: "Analyze release", done: hasAnalysis, to: hasRelease ? `/products/${demo.releases[0].productId}/releases/${demo.releases[0].id}/analyze` : "/products" },
    { label: "Review initial findings", done: hasReview, to: "/findings" },
    { label: "Assign an authorized approver and configure notifications", done: hasApprover && notificationsConfigured, to: hasApprover ? "/settings/notifications" : "/settings/team" },
  ];

  if (setupMode === "replace") return <main className="page"><SetupHero steps={setupSteps}/></main>;

  return (
    <main className="page">
      <PageHeader
        title="Home"
        description="What needs action now, why, by when, and who owns it."
      />

      {monitoring || monitoringNeedsAttention ? (
        <section className={`notice${monitoringNeedsAttention ? " notice-warning" : ""}`} aria-label="Monitoring status">
          <strong>{monitoringNeedsAttention ? "Monitoring needs attention." : "Monitoring is healthy."}</strong>{" "}
          {monitoring
            ? monitoringNeedsAttention
              ? `${monitoringIssueCount} supported releases need monitoring configuration or fresh coverage.`
              : `${monitoring.healthy} of ${monitoring.supportedReleases} supported releases have current coverage.`
            : `${degraded.map((item) => "version" in item ? item.version : item.name).join(", ")} ${degraded.length === 1 ? "has" : "have"} incomplete source coverage.`}
          {" "}<Link className="text-link" to={scopedPath("/compliance", scope, { view: "monitoring" })}>Review monitoring</Link>
        </section>
      ) : null}

      <section className="metrics-grid" aria-label="Action summary">
        <MetricCard label="Deadlines at risk" value={deadlinesAtRisk} detail="Overdue or due soon" tone="urgent" to={scopedPath("/compliance", scope, { view: "deadlines" })} />
        <MetricCard label="Findings awaiting action" value={needsReview} detail="Review or decision required" tone="high" to={scopedPath("/findings", scope)} />
        <MetricCard label="Incomplete or stale evidence" value={incompleteEvidence} detail="Evidence needs attention" to={scopedPath("/compliance", scope, { view: "evidence" })} />
      </section>

      <div className="split-layout">
        <section className="panel">
          <SectionHeader title="Prioritized actions" description="Ordered by regulatory urgency, exploit evidence, and deadline." action={<Link className="text-link" to={scopedPath("/compliance", scope)}>View all</Link>} />
          <ul className="priority-list">
            {activeActions.slice(0, 7).map((item) => {
              const product = demo.selectors.product(item.productId);
              const release = item.releaseId ? demo.selectors.release(item.releaseId) : undefined;
              return (
                <li className="priority-item" key={item.id}>
                  <span className={`priority-marker ${item.priority}`} aria-hidden="true" />
                  <div className="item-main">
                    <Link to={item.targetUrl}>{item.title}</Link>
                    <p>{item.reason}</p>
                    <p>{product?.name}{release ? ` · ${release.version}` : ""} · {memberName(demo.state.members, item.ownerId)}</p>
                  </div>
                  <div className="item-meta">
                    <span className={item.priority === "urgent" ? "danger-text" : ""}>{relativeDate(item.dueAt)}</span>
                  </div>
                </li>
              );
            })}
            {!activeActions.length ? <li className="empty-state"><strong>No action needed</strong><p>There is no open work in this scope.</p></li> : null}
          </ul>
        </section>

        <section className="panel">
          <SectionHeader title="Recent changes" description="Evidence, decisions, monitoring, and documents." />
          <ul className="activity-list">
            {recentChanges.slice(0, 5).map((activity) => (
              <li className="activity-item" key={activity.id}>
                <span className="activity-icon" aria-hidden="true">{activity.type.slice(0, 1).toUpperCase()}</span>
                <div className="item-main">
                  {activity.targetUrl ? <Link to={activity.targetUrl}>{activity.title}</Link> : <strong>{activity.title}</strong>}
                  <p>{activity.detail}</p>
                </div>
                <div className="item-meta"><span>{formatDate(activity.at, true)}</span></div>
              </li>
            ))}
            {!recentChanges.length ? <li className="empty-state"><strong>No recent changes</strong><p>Monitoring and workflow changes will appear here.</p></li> : null}
          </ul>
        </section>
      </div>
    </main>
  );
}

function cadenceLabel(minutes: number[]): string {
  if (!minutes.length) return "Not configured";
  return minutes.map((value) => value === 60 ? "Hourly" : value % 1440 === 0 ? `Every ${value / 1440}d` : value % 60 === 0 ? `Every ${value / 60}h` : `Every ${value}m`).join(", ");
}

function sourceName(source: string): string {
  return ({ osv: "OSV", cisa_kev: "CISA KEV", epss: "EPSS", native_advisory: "Native advisories", vendor_advisory: "Vendor advisories" } as Record<string, string>)[source] ?? source.replaceAll("_", " ");
}

function SetupHero({ steps }: { steps: Array<{ label: string; done: boolean; to: string }> }) {
  const doneCount = steps.filter((s) => s.done).length;
  const nextStep = steps.find((s) => !s.done);
  const percent = Math.round((doneCount / steps.length) * 100);

  return (
    <section className="setup-hero" aria-label="Welcome">
      <div className="setup-hero-illustration" aria-hidden="true">
        <svg viewBox="0 0 140 140" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="shieldGrad" x1="70" y1="10" x2="70" y2="130" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity=".18" />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity=".06" />
            </linearGradient>
            <linearGradient id="shieldStroke" x1="70" y1="10" x2="70" y2="130" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity=".5" />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity=".2" />
            </linearGradient>
          </defs>
          <path d="M70 8 L125 30 C125 30 128 85 70 128 C12 85 15 30 15 30 Z" fill="url(#shieldGrad)" stroke="url(#shieldStroke)" strokeWidth="2.5" strokeLinejoin="round" />
          <path d="M70 22 L115 40 C115 40 117 82 70 118 C23 82 25 40 25 40 Z" fill="none" stroke="var(--accent)" strokeWidth="1.2" strokeOpacity=".12" strokeLinejoin="round" />
          <circle cx="70" cy="68" r="26" fill="var(--accent)" fillOpacity=".12" />
          <path d="M56 68 L65 77 L84 58" fill="none" stroke="var(--accent)" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>

      <h1>Welcome to Actis</h1>
      <p>Set up your workspace to establish release evidence and continuous CRA monitoring.</p>

      <div className="panel setup-card">
        <div className="setup-progress">
          <div className="setup-progress-track">
            <span style={{ width: `${percent}%` }} />
          </div>
          <span className="setup-progress-label">{doneCount} of {steps.length}</span>
        </div>
        <ol className="setup-list">
          {steps.map((item, index) => {
            const isActive = !item.done && steps.slice(0, index).every((step) => step.done);
            return (
              <li className={item.done ? "done" : isActive ? "active-step" : ""} key={item.label}>
                <span aria-hidden="true">{item.done ? "✓" : index + 1}</span>
                <div>
                  <strong>{item.label}</strong>
                  <small>{item.done ? "Complete" : "Not started"}</small>
                </div>
              </li>
            );
          })}
        </ol>
        <div className="setup-cta">
          {nextStep ? (
            <Link className="button button-primary" to={nextStep.to}>
              {doneCount === 0 ? "Get started" : "Continue setup"}
            </Link>
          ) : null}
        </div>
      </div>
    </section>
  );
}
