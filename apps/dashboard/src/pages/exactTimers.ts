import type { Finding, Product, ComplianceItem } from "../data/types";
import { craReportingWindows, remediationDue } from "./findingDeadlines";

export interface ExactTimerResult {
  isOverdue: boolean;
  days: number;
  hours: number;
  minutes: number;
  totalMinutes: number;
  countdownText: string;
  exactDateText: string;
  isoDate: string;
  urgency: "urgent" | "high" | "normal";
  sourceLabel?: string;
}

export function computeExactTimer(
  targetIsoDate?: string,
  sourceLabel?: string,
  referenceTime = Date.now()
): ExactTimerResult | undefined {
  if (!targetIsoDate) return undefined;
  const targetTime = new Date(targetIsoDate).getTime();
  if (isNaN(targetTime)) return undefined;

  const diffMs = targetTime - referenceTime;
  const isOverdue = diffMs < 0;
  const absMs = Math.abs(diffMs);

  const totalMinutes = Math.floor(absMs / 60_000);
  const days = Math.floor(totalMinutes / (24 * 60));
  const hours = Math.floor((totalMinutes % (24 * 60)) / 60);
  const minutes = totalMinutes % 60;

  let countdownText = "";
  if (days > 0) {
    countdownText = `${days}d ${hours}h left`;
  } else if (hours > 0) {
    countdownText = `${hours}h ${minutes}m left`;
  } else {
    countdownText = `${minutes}m left`;
  }

  if (isOverdue) {
    if (days > 0) {
      countdownText = `${days}d ${hours}h overdue`;
    } else if (hours > 0) {
      countdownText = `${hours}h ${minutes}m overdue`;
    } else {
      countdownText = `${minutes}m overdue`;
    }
  }

  const dateObj = new Date(targetIsoDate);
  const exactDateText = new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(dateObj);

  let urgency: "urgent" | "high" | "normal" = "normal";
  if (isOverdue || (!isOverdue && absMs <= 24 * 3_600_000)) {
    urgency = "urgent";
  } else if (!isOverdue && absMs <= 72 * 3_600_000) {
    urgency = "high";
  }

  return {
    isOverdue,
    days,
    hours,
    minutes,
    totalMinutes,
    countdownText,
    exactDateText,
    isoDate: targetIsoDate,
    urgency,
    sourceLabel,
  };
}

/**
 * Computes all deadlines for a finding:
 * - CRA 24h Early Warning (if KEV or actively exploited)
 * - CRA 72h Full Notification (if KEV or actively exploited)
 * - Remediation Due (internal fix target)
 */
export function getFindingTimers(finding: Finding, referenceTime = Date.now()): {
  earlyWarning?: ExactTimerResult;
  fullNotification?: ExactTimerResult;
  remediation?: ExactTimerResult;
  mostUrgent?: ExactTimerResult;
} {
  const windows = craReportingWindows(finding);
  const earlyWarning = windows?.early
    ? computeExactTimer(windows.early, "CRA 24h Early Warning", referenceTime)
    : undefined;
  const fullNotification = windows?.full
    ? computeExactTimer(windows.full, "CRA 72h Notification", referenceTime)
    : undefined;

  const remDate = remediationDue(finding);
  const remediation = remDate
    ? computeExactTimer(remDate, "Remediation target", referenceTime)
    : undefined;

  // Find most urgent timer for this finding
  const timers = [earlyWarning, fullNotification, remediation].filter(
    (t): t is ExactTimerResult => Boolean(t)
  );

  timers.sort((a, b) => new Date(a.isoDate).getTime() - new Date(b.isoDate).getTime());

  return {
    earlyWarning,
    fullNotification,
    remediation,
    mostUrgent: timers[0],
  };
}

/**
 * Computes the single most urgent timer for a product across all its:
 * - Open findings (CRA 24h/72h windows and remediation targets)
 * - Compliance obligations (product.nextDeadline, complianceItems)
 */
export function getProductMostUrgentTimer(
  product: Product,
  findings: Finding[],
  complianceItems: ComplianceItem[],
  referenceTime = Date.now()
): ExactTimerResult | undefined {
  const candidates: ExactTimerResult[] = [];

  // 1. Product's nextDeadline
  if (product.nextDeadline) {
    const timer = computeExactTimer(product.nextDeadline, "Next obligation", referenceTime);
    if (timer) candidates.push(timer);
  }

  // 2. Open findings in this product
  const productFindings = findings.filter(
    (f) => f.productId === product.id && f.status !== "resolved"
  );
  for (const finding of productFindings) {
    const timers = getFindingTimers(finding, referenceTime);
    if (timers.earlyWarning) {
      candidates.push({
        ...timers.earlyWarning,
        sourceLabel: `${finding.reference} 24h Early Warning`,
      });
    }
    if (timers.remediation) {
      candidates.push({
        ...timers.remediation,
        sourceLabel: `${finding.reference} Fix`,
      });
    }
  }

  // 3. Unresolved compliance items in this product
  const productCompliance = complianceItems.filter(
    (item) => item.productId === product.id && (item.lifecycleStatus ? item.lifecycleStatus !== "resolved" : item.status !== "complete")
  );
  for (const item of productCompliance) {
    if (item.dueAt) {
      const timer = computeExactTimer(item.dueAt, item.title, referenceTime);
      if (timer) candidates.push(timer);
    }
  }

  if (!candidates.length) return undefined;

  // Sort earliest target date first
  candidates.sort((a, b) => new Date(a.isoDate).getTime() - new Date(b.isoDate).getTime());
  return candidates[0];
}
