import type { ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Download,
  FileArchive,
  FileCheck2,
  RadioTower,
  ShieldAlert,
  UploadCloud,
} from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { Breadcrumbs, PageHeader } from "./PageKit";
import "./pages.css";

export type ClientDemoView = "portfolio" | "upload" | "alert" | "finding" | "documents";

type PortfolioRow = {
  name: string;
  release: string;
  state: string;
  stateTone: "success" | "danger" | "warning";
  monitoring: string;
  monitoringTone: "success" | "warning";
  detail: string;
};

const portfolio: PortfolioRow[] = [
  { name: "Smart Camera", release: "v2.1.4", state: "Compliant", stateTone: "success", monitoring: "Healthy", monitoringTone: "success", detail: "Evidence complete" },
  { name: "Home Hub", release: "v1.8.0", state: "Urgent security finding", stateTone: "danger", monitoring: "Healthy", monitoringTone: "success", detail: "Critical action required" },
  { name: "Smart Lock", release: "v1.4.2", state: "CRA deadline approaching", stateTone: "warning", monitoring: "Healthy", monitoringTone: "success", detail: "Due in 6 days" },
  { name: "Edge Gateway", release: "v3.0.7", state: "Review required", stateTone: "warning", monitoring: "Degraded", monitoringTone: "warning", detail: "Last signal 2 hours ago" },
];

function DemoClock({ value }: { value: string }) {
  return (
    <div className="client-demo-clockbar" role="timer" aria-label={`CRA early warning due in ${value}`}>
      <span><ShieldAlert size={18} aria-hidden="true" /> CRA 24-hour reporting window</span>
      <strong>{value}</strong>
    </div>
  );
}

function TonePill({ tone, children }: { tone: "success" | "danger" | "warning" | "neutral"; children: ReactNode }) {
  return <span className={`client-demo-pill client-demo-pill--${tone}`}>{children}</span>;
}

function PortfolioView() {
  return (
    <main className="page client-demo-page" data-client-demo-view="portfolio">
      <PageHeader eyebrow="Portfolio" title="Products" description="Security, monitoring, and CRA readiness across active product releases." />
      <section className="panel client-demo-portfolio">
        <div className="client-demo-portfolio__summary">
          <div><strong>4</strong><span>Monitored products</span></div>
          <div><strong className="danger-text">1</strong><span>Urgent action</span></div>
          <div><strong>1</strong><span>Upcoming deadline</span></div>
          <div><strong>1</strong><span>Degraded monitor</span></div>
        </div>
        <div className="data-table-wrap">
          <table className="data-table client-demo-table">
            <thead><tr><th>Product</th><th>Active release</th><th>Security &amp; compliance</th><th>Monitoring</th><th>Current state</th></tr></thead>
            <tbody>{portfolio.map((item) => (
              <tr key={item.name} className={item.name === "Home Hub" ? "client-demo-row--urgent" : undefined}>
                <td><div className="cell-primary"><strong>{item.name}</strong><small>Connected product</small></div></td>
                <td><strong>{item.release}</strong></td>
                <td><TonePill tone={item.stateTone}>{item.state}</TonePill></td>
                <td><TonePill tone={item.monitoringTone}><RadioTower size={13} aria-hidden="true" />{item.monitoring}</TonePill></td>
                <td><span className={item.stateTone === "danger" ? "danger-text" : "muted"}>{item.detail}</span></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </section>
    </main>
  );
}

function UploadView() {
  return (
    <main className="page client-demo-page" data-client-demo-view="upload">
      <Breadcrumbs items={[{ label: "Products" }, { label: "Home Hub" }, { label: "Register release" }]} />
      <PageHeader eyebrow="Home Hub · Product scope" title="Register Home Hub release" description="Add the release artifact that will be assessed and continuously monitored." />
      <section className="panel analysis-card client-demo-upload">
        <div className="client-demo-upload__head">
          <div className="client-demo-step client-demo-step--done"><CheckCircle2 size={18} />Release details</div>
          <div className="client-demo-step client-demo-step--active"><UploadCloud size={18} />Upload firmware</div>
          <div className="client-demo-step">Confirm</div>
        </div>
        <div className="client-demo-upload__grid">
          <div>
            <p className="eyebrow">Release</p>
            <h2>Home Hub firmware v1.8.0</h2>
            <p className="page-description">Production release · EU market · Home Hub</p>
          </div>
          <label className="upload-zone client-demo-upload-zone">
            <FileArchive size={34} aria-hidden="true" />
            <strong>Home Hub firmware v1.8.0</strong>
            <span>Firmware archive · 18.6 MB · Ready to upload</span>
            <input type="file" aria-label="Choose Home Hub firmware" />
          </label>
        </div>
        <div className="inline-actions client-demo-upload__actions">
          <button type="button">Back</button>
          <button className="button button-primary" type="button">Upload firmware</button>
        </div>
      </section>
    </main>
  );
}

function AlertView() {
  return (
    <main className="page client-demo-page" data-client-demo-view="alert">
      <DemoClock value="24:00:00" />
      <section className="client-demo-critical-alert" role="alert">
        <span className="client-demo-critical-alert__icon"><AlertTriangle size={34} aria-hidden="true" /></span>
        <div>
          <p className="eyebrow">Home Hub v1.8.0</p>
          <h1>Critical vulnerability detected</h1>
          <p>CVE-2021-44228 affects a confirmed component in this release. CRA early-warning review is now open.</p>
        </div>
        <TonePill tone="danger">Action required</TonePill>
      </section>
      <section className="panel panel-pad client-demo-alert-context">
        <div><span>Finding</span><strong>CVE-2021-44228</strong></div>
        <div><span>Component</span><strong>log4j-core 2.14.1</strong></div>
        <div><span>Risk</span><strong className="danger-text">Remote code execution</strong></div>
        <div><span>Release</span><strong>Home Hub v1.8.0</strong></div>
      </section>
    </main>
  );
}

function FindingView({ clock }: { clock: string }) {
  return (
    <main className="page client-demo-page" data-client-demo-view="finding">
      <DemoClock value={clock} />
      <Breadcrumbs items={[{ label: "Findings" }, { label: "Home Hub v1.8.0" }, { label: "CVE-2021-44228" }]} />
      <PageHeader
        eyebrow="Critical finding · Action required"
        title="CVE-2021-44228"
        description="Remote code execution risk in Apache Log4j"
        actions={<div className="inline-actions"><TonePill tone="danger">Critical</TonePill><TonePill tone="danger">CISA KEV</TonePill></div>}
      />
      <div className="client-demo-finding-grid">
        <section className="panel panel-pad client-demo-finding-main">
          <div className="client-demo-facts">
            <div><span>Affected product</span><strong>Home Hub v1.8.0</strong></div>
            <div><span>Component</span><strong>log4j-core 2.14.1</strong></div>
            <div><span>Risk</span><strong>Remote code execution</strong></div>
            <div><span>Response</span><strong>Decision required</strong></div>
          </div>
          <div className="client-demo-evidence-row client-demo-evidence-row--confirmed">
            <CheckCircle2 size={24} aria-hidden="true" />
            <div><strong>Component presence confirmed</strong><span>Exact package and version identified in the Home Hub firmware evidence.</span></div>
          </div>
          <div className="client-demo-evidence-row client-demo-evidence-row--pending">
            <Clock3 size={24} aria-hidden="true" />
            <div><strong>Reachability not yet assessed</strong><span>Presence is confirmed; execution-path evidence is still required before exploitability is determined.</span></div>
          </div>
        </section>
        <aside className="panel panel-pad client-demo-decision">
          <p className="eyebrow">Risk assessment</p>
          <h2>Urgent review required</h2>
          <p>This vulnerability is known to be actively exploited. Confirm reachability, contain exposed services, and prepare the early-warning record.</p>
          <div className="client-demo-decision__meta"><span>Severity</span><strong className="danger-text">Critical</strong></div>
          <div className="client-demo-decision__meta"><span>Public exploitation</span><strong>Confirmed</strong></div>
          <div className="client-demo-decision__meta"><span>Remediation target</span><strong>Upgrade Log4j</strong></div>
          <button className="button button-primary" type="button">Record decision</button>
        </aside>
      </div>
    </main>
  );
}

function DocumentsView({ clock }: { clock: string }) {
  return (
    <main className="page client-demo-page" data-client-demo-view="documents">
      <DemoClock value={clock} />
      <Breadcrumbs items={[{ label: "Compliance" }, { label: "Home Hub v1.8.0" }, { label: "Documents" }]} />
      <PageHeader eyebrow="Release documents" title="Home Hub v1.8.0" description="Regulatory records generated from the current release evidence and finding decisions." />
      <section className="panel client-demo-documents">
        <div className="client-demo-documents__tabs"><span>Overview</span><span>Findings</span><span>Compliance</span><span className="active">Documents</span></div>
        <div className="client-demo-document-row">
          <span className="client-demo-document-icon"><FileCheck2 size={27} aria-hidden="true" /></span>
          <div className="cell-primary">
            <strong>CRA 24-hour Early Warning</strong>
            <small>Incident notification · Home Hub v1.8.0 · Prepared for review</small>
          </div>
          <TonePill tone="warning">Draft ready</TonePill>
          <div className="client-demo-document-meta"><span>Updated</span><strong>Just now</strong></div>
          <button className="button client-demo-download" type="button"><Download size={17} aria-hidden="true" />Download</button>
        </div>
      </section>
    </main>
  );
}

export function ClientDemoPage({ view }: { view: ClientDemoView }) {
  const [params] = useSearchParams();
  const clock = params.get("clock") ?? "23:59:59";
  if (view === "portfolio") return <PortfolioView />;
  if (view === "upload") return <UploadView />;
  if (view === "alert") return <AlertView />;
  if (view === "finding") return <FindingView clock={clock} />;
  return <DocumentsView clock={clock} />;
}
