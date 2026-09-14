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
import { Link, useSearchParams } from "react-router-dom";
import { Breadcrumbs, PageHeader } from "./PageKit";
import "./pages.css";

export type ClientDemoView = "portfolio" | "product" | "upload" | "alert" | "finding" | "documents";

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
  { name: "Home Hub", release: "v1.7.4", state: "Urgent security finding", stateTone: "danger", monitoring: "Healthy", monitoringTone: "success", detail: "Critical action required" },
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
                <td><div className="cell-primary">{item.name === "Home Hub" ? <Link className="client-demo-product-link" to="/products/client-demo/home-hub?product=product-home-hub">{item.name}</Link> : <strong>{item.name}</strong>}<small>Connected product</small></div></td>
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

function ProductView() {
  return (
    <main className="page client-demo-page" data-client-demo-view="product">
      <Breadcrumbs items={[{ label: "Products" }, { label: "Home Hub" }]} />
      <section className="panel client-demo-product-hero">
        <div className="client-demo-product-avatar">HH</div>
        <div>
          <p className="eyebrow">Connected product · Product scope</p>
          <h1>Home Hub</h1>
          <p>Residential connectivity hub for the EU market.</p>
        </div>
        <Link className="button button-primary client-demo-register" to="/products/client-demo/upload?product=product-home-hub">Register new release</Link>
      </section>
      <section className="panel client-demo-release-current">
        <div><span>Current active release</span><strong>v1.7.4</strong></div>
        <div><span>Monitoring</span><TonePill tone="success">Healthy</TonePill></div>
        <div><span>CRA readiness</span><TonePill tone="success">Compliant</TonePill></div>
        <div><span>Last assessment</span><strong>12 Sep 2026</strong></div>
      </section>
    </main>
  );
}

function UploadView({ selected }: { selected: boolean }) {
  return (
    <main className="page client-demo-page" data-client-demo-view="upload">
      <Breadcrumbs items={[{ label: "Products" }, { label: "Home Hub" }, { label: "New release v1.8.0" }]} />
      <PageHeader eyebrow="Home Hub · New release" title="Register Home Hub v1.8.0" description="Add the new release artifact that will be assessed and continuously monitored." />
      <section className="panel analysis-card client-demo-upload">
        <div className="client-demo-upload__head">
          <div className="client-demo-step client-demo-step--done"><CheckCircle2 size={18} />Release details</div>
          <div className="client-demo-step client-demo-step--active"><UploadCloud size={18} />Upload firmware</div>
          <div className="client-demo-step">Confirm</div>
        </div>
        <div className="client-demo-upload__grid">
          <div>
            <p className="eyebrow">Release</p>
            <h2>New release · v1.8.0</h2>
            <p className="page-description">Production channel · EU market · Not yet analyzed</p>
          </div>
          <label className={`upload-zone client-demo-upload-zone${selected ? " client-demo-upload-zone--selected" : ""}`} htmlFor="client-release-file">
            <FileArchive size={34} aria-hidden="true" />
            <strong>{selected ? "Home Hub firmware v1.8.0.zip" : "Select release file"}</strong>
            <span>{selected ? "Firmware archive · 18.6 MB · Ready to analyze" : "Choose the signed firmware archive for new release v1.8.0"}</span>
            <input id="client-release-file" type="file" aria-label="Select release file" />
          </label>
        </div>
        <div className="inline-actions client-demo-upload__actions">
          <button type="button">Back</button>
          {selected ? <Link className="button button-primary client-demo-upload-action" to="/products/client-demo/alert?product=product-home-hub&release=release-hub-1-8-0">Upload &amp; analyze</Link> : <button className="button button-primary" type="button" disabled>Upload &amp; analyze</button>}
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
          <h1>New release analysis found a critical vulnerability</h1>
          <p>CVE-2021-44228 affects a confirmed component in Home Hub v1.8.0. CRA early-warning review is now open.</p>
        </div>
        <Link className="button button-primary client-demo-review-finding" to="/findings/client-demo?product=product-home-hub&release=release-hub-1-8-0&clock=23%3A59%3A59">Review finding</Link>
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
      <nav className="panel client-demo-workspace-tabs" aria-label="Home Hub release sections">
        <span>Overview</span><span className="active">Findings</span><span>Compliance</span><Link className="client-demo-documents-tab" to="/compliance/client-demo?product=product-home-hub&release=release-hub-1-8-0&clock=23%3A59%3A56">Documents</Link>
      </nav>
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
  if (view === "product") return <ProductView />;
  if (view === "upload") return <UploadView selected={params.get("selected") === "1"} />;
  if (view === "alert") return <AlertView />;
  if (view === "finding") return <FindingView clock={clock} />;
  return <DocumentsView clock={clock} />;
}
