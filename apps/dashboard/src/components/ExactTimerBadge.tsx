import { Clock, AlertTriangle } from "lucide-react";
import type { ExactTimerResult } from "../pages/exactTimers";

interface ExactTimerBadgeProps {
  timer?: ExactTimerResult;
  showDate?: boolean;
  showLabel?: boolean;
  compact?: boolean;
}

export function ExactTimerBadge({
  timer,
  showDate = true,
  showLabel = true,
  compact = false,
}: ExactTimerBadgeProps) {
  if (!timer) {
    return <span className="muted" style={{ fontSize: 13 }}>No active deadline</span>;
  }

  const isUrgent = timer.urgency === "urgent";
  const isHigh = timer.urgency === "high";
  const tooltipTitle = `Exact deadline: ${timer.exactDateText}${timer.sourceLabel ? ` (${timer.sourceLabel})` : ""}`;

  return (
    <div
      className={`exact-timer-badge ${
        isUrgent
          ? "exact-timer-badge--urgent"
          : isHigh
          ? "exact-timer-badge--high"
          : "exact-timer-badge--normal"
      } ${compact ? "exact-timer-badge--compact" : ""}`}
      title={tooltipTitle}
    >
      <div className="exact-timer-badge__top">
        {timer.isOverdue ? (
          <AlertTriangle size={13} className="exact-timer-icon exact-timer-icon--danger" />
        ) : (
          <Clock size={13} className="exact-timer-icon" />
        )}
        <span className="exact-timer-countdown mono">{timer.countdownText}</span>
      </div>

      {!compact && ((showLabel && timer.sourceLabel) || showDate) ? (
        <div className="exact-timer-badge__sub">
          {showLabel && timer.sourceLabel ? (
            <span className="exact-timer-label">{timer.sourceLabel}</span>
          ) : null}
          {showDate ? <span className="exact-timer-date">{timer.exactDateText}</span> : null}
        </div>
      ) : null}
    </div>
  );
}
