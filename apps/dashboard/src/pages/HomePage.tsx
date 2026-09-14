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
  const actionTotal = counters?.actionTotal ?? activeActions.length;
  const needsReview = counters?.findingsNeedingAction ?? demo.findings.filter((item) => matchesScope(item, scope) && (item.status === "needs_review" || item.status === "action_required")).length;
  const dueSoon = counters?.dueSoonObligations ?? activeActions.filter((item) => item.dueAt && new Date(item.dueAt).getTime() - Date.now() <= 7 * 86_400_000).length;
  const scopedReleases = demo.releases.filter((item) => matchesScope(item, scope));
  const scopedProducts = demo.products.filter((item) => !scope.productId || item.id === scope.productId);
  const degraded = scope.releaseId
    ? scopedReleases.filter((item) => item.monitoringHealth === "degraded" || item.monitoringHealth === "failed")
    : scopedProducts.filter((item) => item.monitoringHealth === "degraded" || item.monitoringHealth === "failed");
  const monitoring = isScoped ? undefined : demo.state.home?.monitoring;
  const monitoringNeedsAttention = monitoring ? monitoring.state !== "healthy" : degraded.length > 0;
  const monitoringIssueCount = monitoring ? monitoring.degraded + monitoring.failed + monitoring.stale + monitoring.inactive + monitoring.notConfigured : degraded.length;
  const recentChanges = demo.state.activities.filter((item) => matchesScope(item, scope));

  return (
    <main className="page">
      <PageHeader
        eyebrow="Compliance operations"
        title={`Good morning, ${demo.currentUser.name.split(" ")[0]}`}
        description="What needs attention across your products and supported releases."
        actions={<Link className="button button-primary" to="/products">Review portfolio</Link>}
      />

      <section className="metrics-grid" aria-label="Action summary">
        <MetricCard label="Action needed" value={actionTotal} detail="Open prioritized work" tone="urgent" />
        <MetricCard label="Needs review" value={needsReview} detail="Findings awaiting a decision" tone="high" />
        <MetricCard label="Due soon" value={dueSoon} detail="Obligations within seven days" />
      </section>

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
          </ul>
        </section>

        <section className="panel">
          <SectionHeader title="Recent changes" description="Evidence, decisions, monitoring, and documents." />
          <ul className="activity-list">
            {recentChanges.slice(0, 7).map((activity) => (
              <li className="activity-item" key={activity.id}>
                <span className="activity-icon" aria-hidden="true">{activity.type.slice(0, 1).toUpperCase()}</span>
                <div className="item-main">
                  {activity.targetUrl ? <Link to={activity.targetUrl}>{activity.title}</Link> : <strong>{activity.title}</strong>}
                  <p>{activity.detail}</p>
                </div>
                <div className="item-meta"><span>{formatDate(activity.at, true)}</span></div>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </main>
  );
}
