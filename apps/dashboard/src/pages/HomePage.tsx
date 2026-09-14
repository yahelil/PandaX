import { Link, useSearchParams } from "react-router-dom";
import { useDemo } from "../data/DemoProvider";
import { MetricCard, PageHeader, SectionHeader, StatusPill, formatDate, memberName, relativeDate } from "./PageKit";
import "./pages.css";
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
  const firstRun = !isScoped && !(hasProduct && hasRelease && hasAnalysis && hasReview && hasApprover && notificationsConfigured);

  if (firstRun) {
    const steps = [
      { label: "Create product", done: hasProduct, to: "/products" },
      { label: "Register release", done: hasRelease, to: hasProduct ? `/products/${demo.products[0].id}` : "/products" },
      { label: "Analyze release", done: hasAnalysis, to: hasRelease ? `/products/${demo.releases[0].productId}/releases/${demo.releases[0].id}/analyze` : "/products" },
      { label: "Review initial findings", done: hasReview, to: "/findings" },
      { label: "Assign an authorized approver and configure notifications", done: hasApprover && notificationsConfigured, to: "/settings/team" },
    ];
    return <main className="page"><PageHeader title="Set up Actis" description="Complete these steps to establish release evidence and continuous CRA monitoring."/><section className="panel setup-panel"><ol className="setup-list">{steps.map((item, index)=><li className={item.done ? "done" : ""} key={item.label}><span aria-hidden="true">{item.done ? "✓" : index + 1}</span><div><strong>{item.label}</strong><small>{item.done ? "Complete" : "Not started"}</small></div>{!item.done && steps.slice(0,index).every((step)=>step.done) ? <Link className="button button-primary" to={item.to}>Continue setup</Link> : null}</li>)}</ol></section></main>;
  }

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
                    <StatusPill value={item.priority} />
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
