import { type FormEvent, useEffect, useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { usePermission } from '../auth'
import { useDemo } from '../data/DemoProvider'
import type { DecisionKind, Remediation } from '../data/types'
import { Breadcrumbs, EmptyState, PageHeader, SectionHeader, StatusPill, formatDate, memberName, relativeDate, titleCase } from './PageKit'
import { craReportingWindows, remediationDue } from './findingDeadlines'
import { downloadFile } from './downloadFile'
import './pages.css'

export function FindingDetailPage() {
  const { findingId = '' } = useParams()
  const location = useLocation()
  const demo = useDemo()
  const canDecide = usePermission('decide_findings')
  const canRemediate = usePermission('manage_remediation')
  const canGenerateReport = usePermission('generate_findings_report')
  const finding = demo.findings.find((item) => item.id === findingId)
  const [decision, setDecision] = useState<DecisionKind>('affected')
  const [rationale, setRationale] = useState('')
  const [plan, setPlan] = useState(finding?.remediation.plan ?? '')
  const [targetDate, setTargetDate] = useState(finding?.remediation.targetDate?.slice(0, 10) ?? '')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    void demo.actions.loadFindingDetail(findingId, { signal: controller.signal }).catch(() => undefined)
    return () => controller.abort()
  }, [demo.actions, findingId])

  useEffect(() => {
    const section = location.hash.slice(1)
    if (!finding || (section !== 'risk-decision' && section !== 'remediation')) return
    const frame = requestAnimationFrame(() => document.getElementById(section)?.scrollIntoView())
    return () => cancelAnimationFrame(frame)
  }, [finding, location.hash])

  if (!finding) {
    return <EmptyState title="Finding not found" body="This finding may have been resolved or is outside the selected scope." action={<Link className="button" to="/findings">Back to findings</Link>} />
  }

  const product = demo.selectors.product(finding.productId)
  const release = demo.selectors.release(finding.releaseId)
  const evidence = demo.state.evidence.filter((item) => finding.evidenceIds.includes(item.id))
  const reporting = craReportingWindows(finding)
  const perform = async (operation: () => unknown | Promise<unknown>, success: string): Promise<boolean> => {
    setBusy(true)
    setMessage('')
    try {
      await operation()
      setMessage(success)
      return true
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to save the finding update.')
      return false
    } finally {
      setBusy(false)
    }
  }
  const decide = (event: FormEvent) => {
    event.preventDefault()
    void perform(
      () => demo.actions.decideFinding({ findingId: finding.id, decision, rationale }),
      'Decision recorded in the audit history.',
    ).then((saved) => { if (saved) setRationale('') })
  }
  const saveRemediation = (event: FormEvent) => {
    event.preventDefault()
    void perform(
      () => demo.actions.updateRemediation({ findingId: finding.id, status: 'planned', plan, targetDate: targetDate || undefined }),
      'Remediation plan updated.',
    )
  }
  const generateReport = () => {
    void perform(async () => {
      const file = await demo.actions.generateFindingsReport(finding.productId, finding.releaseId)
      downloadFile(file, `actis-${finding.releaseId}-findings-report.json`)
    }, 'Release findings report generated and downloaded.')
  }

  return <main className="page">
    <Breadcrumbs items={[{ label: 'Findings', to: '/findings' }, { label: finding.reference }]} />
    <PageHeader eyebrow={`${product?.name} · ${release?.version}`} title={`${finding.reference}: ${finding.title}`} description={finding.summary} actions={<div className="inline-actions"><StatusPill value={finding.priority} /><StatusPill value={finding.status} label={finding.status === 'action_required' ? 'Fix required' : undefined} />{canGenerateReport ? <button type="button" className="button button-primary" disabled={busy} onClick={generateReport}>Download findings report</button> : null}</div>} />
    <section className="panel detail-hero">
      <div className="detail-badges"><StatusPill value={finding.severity} />{finding.kev ? <span className="status-pill status-urgent">CISA KEV</span> : null}{finding.activelyExploited ? <span className="status-pill status-urgent">Actively exploited</span> : null}<StatusPill value={finding.affectedness} /><StatusPill value={finding.reachability} /></div>
      <h2>Why this needs attention</h2><p>{finding.actionReason}</p>
      <dl className="definition-grid">
        <div><dt>Component</dt><dd>{finding.component} {finding.componentVersion}</dd></div>
        <div><dt>CVSS</dt><dd>{finding.cvss.toFixed(1)} · {titleCase(finding.severity)}</dd></div>
        <div><dt>Owner</dt><dd><select className="select-field" value={finding.assigneeId ?? ''} disabled={busy || !canRemediate} title={!canRemediate ? 'Compliance Operator or Organization Admin permission required' : undefined} onChange={(event) => { void perform(() => demo.actions.assignFinding(finding.id, event.target.value || undefined), 'Owner updated.') }}><option value="">Unassigned</option>{demo.state.members.filter((member) => member.status === 'active').map((member) => <option value={member.id} key={member.id}>{member.name}</option>)}</select></dd></div>
        <div><dt>Remediation target (internal)</dt><dd className={finding.priority === 'urgent' ? 'danger-text' : ''}>{relativeDate(remediationDue(finding))} · {formatDate(remediationDue(finding), true)}</dd></div>
      </dl>
      {reporting ? <div className="panel-pad notice"><strong>CRA reporting assessment</strong><p>Potentially reportable active exploitation. Confirm when the manufacturer became aware; the dates below use first detection as a provisional starting point.</p><p>Early warning (24h): {formatDate(reporting.early, true)} · Full notification (72h): {formatDate(reporting.full, true)}</p><p>For an actively exploited vulnerability, the final report is due within 14 days after a corrective or mitigating measure is available. A severe incident has a separate one-month final-report window after its 72-hour notification.</p></div> : null}
    </section>
    {finding.status === 'action_required' ? <div className="notice"><strong>Next action: plan the fix.</strong> This finding was confirmed as affecting the release. <a href="#remediation">Set the remediation plan and target date</a>. If active exploitation is confirmed, assess the CRA notification deadlines above. The downloadable findings report records this decision and remediation status; it is not a CRA notification.</div> : null}
    {message ? <div className="notice" role="status">{message}</div> : null}
    <div className="split-layout">
      <div className="page">
        <section className="panel" id="risk-decision">
          <SectionHeader title="Risk assessment and decision" description="Record a reasoned determination. Evidence remains attached to this release." />
          <form className="setting-section" onSubmit={decide}>
            {!canDecide ? <div className="notice">Only a Security Reviewer or Organization Admin can record risk decisions.</div> : null}
            <div className="field"><label htmlFor="decision">Decision</label><select id="decision" className="select-field" value={decision} disabled={!canDecide} onChange={(event) => setDecision(event.target.value as DecisionKind)}><option value="affected">Affected</option><option value="not_affected">Not affected</option><option value="accepted_risk">Accept risk</option><option value="deferred">Defer decision</option></select></div>
            <div className="field"><label htmlFor="rationale">Rationale</label><textarea id="rationale" className="textarea-field" required minLength={12} value={rationale} disabled={!canDecide} onChange={(event) => setRationale(event.target.value)} placeholder="Explain the decision using the available product and release evidence." /></div>
            <div className="inline-actions"><button className="button-primary" type="submit" disabled={busy || !canDecide}>Record decision</button></div>
          </form>
          <ul className="timeline">{finding.decisions.map((item) => <li key={item.id}><strong>{titleCase(item.decision)} · {memberName(demo.state.members, item.decidedBy)}</strong><span>{formatDate(item.decidedAt, true)}</span><p>{item.rationale}</p></li>)}</ul>
        </section>
        <section className="panel" id="remediation">
          <SectionHeader title="Remediation" description="Define accountable work without turning Actis into a ticketing system." />
          <form className="setting-section" onSubmit={saveRemediation}>
            {!canRemediate ? <div className="notice">Your role can review this remediation plan but cannot change it.</div> : null}
            <div className="field"><label htmlFor="plan">Plan</label><textarea id="plan" className="textarea-field" required value={plan} disabled={!canRemediate} onChange={(event) => setPlan(event.target.value)} placeholder="Describe the update, mitigation, and verification evidence required." /></div>
            <div className="field"><label htmlFor="target">Target date</label><input id="target" className="input-field" type="date" value={targetDate} disabled={!canRemediate} onChange={(event) => setTargetDate(event.target.value)} /></div>
            <div className="inline-actions"><button className="button-primary" disabled={busy || !canRemediate}>Save remediation plan</button>{finding.remediation.status !== 'verified' ? <button type="button" disabled={busy || !canRemediate} onClick={() => { void perform(() => demo.actions.updateRemediation({ findingId: finding.id, status: nextStatus(finding.remediation.status), plan, targetDate: targetDate || undefined }), 'Remediation status advanced.') }}>Advance status</button> : null}</div>
          </form>
        </section>
      </div>
      <aside className="page">
        <section className="panel"><SectionHeader title="Evidence" description={`${evidence.length} records support this assessment.`} />{evidence.map((item) => <article className="evidence-card" key={item.id}><h3>{item.label}</h3><p>{titleCase(item.kind)} · {item.source}</p><p>Collected {formatDate(item.collectedAt, true)}</p>{item.digest ? <code>{item.digest}</code> : null}</article>)}</section>
        <section className="panel"><SectionHeader title="Decision principles" /><div className="panel-pad muted">Affectedness, reachability, and exploit evidence are independent. Record uncertainty directly rather than inferring safety from missing evidence.</div></section>
      </aside>
    </div>
  </main>
}

function nextStatus(status: Remediation['status']): Remediation['status'] {
  return ({ not_started: 'planned', planned: 'in_progress', in_progress: 'verification_pending', verification_pending: 'verified', verified: 'verified' } as const)[status]
}
