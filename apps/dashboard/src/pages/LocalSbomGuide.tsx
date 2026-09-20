import { Check, Copy, Download, ExternalLink, FileCode, ShieldCheck, Terminal } from "lucide-react";
import { useState } from "react";

export const COLLECTOR_DOWNLOAD_URL = "https://github.com/yahelil/PandaX/releases/latest/download/actis-collector-windows-x64.zip";
export const COLLECTOR_LOCAL_URL = "/actis-collector-windows-x64.zip";
export const COLLECTOR_SBOM_COMMAND = '.\\actis-collector.exe sbom "C:\\path\\to\\product" --output ".\\bom.cdx.json"';

export const SYFT_DOWNLOAD_URL = "https://github.com/anchore/syft/releases";
export const SYFT_SBOM_COMMAND = "syft dir:. -o cyclonedx-json=bom.cdx.json";
export const CDXGEN_SBOM_COMMAND = "npx @cyclonedx/cdxgen -o bom.cdx.json";

type Tab = "collector" | "syft" | "cdxgen";

interface Props {
  compact?: boolean;
  productName?: string;
  productVersion?: string;
  onAttachSbom?: (file: File) => void;
}

export function LocalSbomGuide({ compact = false, productName: _productName, productVersion: _productVersion, onAttachSbom: _onAttachSbom }: Props) {
  const [open, setOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>("collector");
  const [copyCommand, setCopyCommand] = useState<string | null>(null);

  const copyText = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyCommand(text);
      setTimeout(() => setCopyCommand(null), 2500);
    } catch {
      // ignore
    }
  };

  return (
    <details
      className={`local-sbom-guide${compact ? " local-sbom-guide--compact" : ""}`}
      onToggle={(event) => setOpen(event.currentTarget.open)}
      style={{ marginTop: 16 }}
    >
      <summary style={{ cursor: "pointer" }}>
        <span className="local-sbom-guide__icon" aria-hidden="true">
          <ShieldCheck size={20} />
        </span>
        <span>
          <strong>Generate an SBOM locally</strong>
          <small>Keep source code on your computer, then upload only the generated JSON.</small>
        </span>
        <span className="local-sbom-guide__show">{open ? "Hide tools" : "Show tools"}</span>
      </summary>

      <div className="local-sbom-guide__body" style={{ padding: 18, display: "grid", gap: 16 }}>
        <div style={{ display: "flex", gap: 6, borderBottom: "1px solid var(--border)", paddingBottom: 8, overflowX: "auto" }}>
          <button
            type="button"
            className={`button button-small ${activeTab === "collector" ? "button-primary" : ""}`}
            onClick={() => setActiveTab("collector")}
            style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
          >
            <ShieldCheck size={14} /> Actis Collector (Windows x64)
          </button>
          <button
            type="button"
            className={`button button-small ${activeTab === "syft" ? "button-primary" : ""}`}
            onClick={() => setActiveTab("syft")}
            style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
          >
            <Terminal size={14} /> Syft (Anchore)
          </button>
          <button
            type="button"
            className={`button button-small ${activeTab === "cdxgen" ? "button-primary" : ""}`}
            onClick={() => setActiveTab("cdxgen")}
            style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
          >
            <FileCode size={14} /> cdxgen (OWASP)
          </button>
        </div>

        {/* Tab 1: Actis Collector */}
        {activeTab === "collector" && (
          <div style={{ display: "grid", gap: 14 }}>
            <div>
              <strong style={{ fontSize: 14 }}>Actis Collector for Windows x64</strong>
              <p className="muted" style={{ margin: "4px 0 0", fontSize: 12.5 }}>
                Offline privacy tool that scans your product directory locally using the embedded Syft engine. Your source code never leaves your computer.
              </p>
            </div>

            <ol style={{ margin: "4px 0", paddingLeft: 20, fontSize: 12.5, display: "grid", gap: 8 }}>
              <li>
                <a
                  className="button"
                  href={COLLECTOR_LOCAL_URL}
                  download="actis-collector-windows-x64.zip"
                  style={{ display: "inline-flex", alignItems: "center", gap: 8 }}
                >
                  <Download size={16} /> Download Windows x64 tool
                </a>
                <span className="muted" style={{ marginLeft: 10, fontSize: 11.5 }}>
                  (Standalone bundle with <code>actis-collector.exe</code> and <code>syft.exe</code>)
                </span>
              </li>
              <li>Extract the ZIP and open PowerShell in the <code>actis-collector</code> folder.</li>
              <li>Run this command, replacing the example path with your product directory or archive:</li>
            </ol>

            <div className="local-command">
              <Terminal size={17} aria-hidden="true" />
              <code>{COLLECTOR_SBOM_COMMAND}</code>
              <button type="button" onClick={() => copyText(COLLECTOR_SBOM_COMMAND)} aria-label="Copy local SBOM command">
                {copyCommand === COLLECTOR_SBOM_COMMAND ? <Check size={16} /> : <Copy size={16} />}
                {copyCommand === COLLECTOR_SBOM_COMMAND ? "Copied" : "Copy"}
              </button>
            </div>

            <p className="local-sbom-guide__privacy" style={{ margin: 0 }}>
              <ShieldCheck size={16} aria-hidden="true" />
              <span>
                <strong>Nothing is uploaded while the tool runs.</strong> Your source stays local. Actis receives only <code>bom.cdx.json</code> if you choose to upload it.
              </span>
            </p>
          </div>
        )}

        {/* Tab 2: Syft */}
        {activeTab === "syft" && (
          <div style={{ display: "grid", gap: 12 }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <strong style={{ fontSize: 14 }}>Syft (Anchore Open Source)</strong>
                <a
                  href={SYFT_DOWNLOAD_URL}
                  target="_blank"
                  rel="noreferrer"
                  className="button button-small"
                  style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
                >
                  <ExternalLink size={14} /> Official Syft Releases
                </a>
              </div>
              <p className="muted" style={{ margin: "4px 0 0", fontSize: 12.5 }}>
                The leading open-source CLI scanner used across Windows, macOS, and Linux to generate CycloneDX and SPDX SBOMs.
              </p>
            </div>

            <ol style={{ margin: "4px 0", paddingLeft: 20, fontSize: 12.5, display: "grid", gap: 6 }}>
              <li>
                <strong>Install:</strong> Windows: <code>winget install anchore.syft</code> · macOS: <code>brew install syft</code> · Linux: <code>curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh</code>
              </li>
              <li>Open your terminal in your project or repository folder.</li>
              <li>Run the scan command:</li>
            </ol>

            <div className="local-command">
              <Terminal size={17} aria-hidden="true" />
              <code>{SYFT_SBOM_COMMAND}</code>
              <button type="button" onClick={() => copyText(SYFT_SBOM_COMMAND)} aria-label="Copy Syft command">
                {copyCommand === SYFT_SBOM_COMMAND ? <Check size={16} /> : <Copy size={16} />}
                {copyCommand === SYFT_SBOM_COMMAND ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        )}

        {/* Tab 3: cdxgen */}
        {activeTab === "cdxgen" && (
          <div style={{ display: "grid", gap: 12 }}>
            <div>
              <strong style={{ fontSize: 14 }}>OWASP CycloneDX Generator (cdxgen)</strong>
              <p className="muted" style={{ margin: "4px 0 0", fontSize: 12.5 }}>
                Zero installation required if you have Node.js installed. Automatically inspects JavaScript, Python, Java, Go, Rust, and .NET.
              </p>
            </div>

            <p style={{ margin: 0, fontSize: 12.5 }}>Run this command directly in your project root:</p>

            <div className="local-command">
              <Terminal size={17} aria-hidden="true" />
              <code>{CDXGEN_SBOM_COMMAND}</code>
              <button type="button" onClick={() => copyText(CDXGEN_SBOM_COMMAND)} aria-label="Copy cdxgen command">
                {copyCommand === CDXGEN_SBOM_COMMAND ? <Check size={16} /> : <Copy size={16} />}
                {copyCommand === CDXGEN_SBOM_COMMAND ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        )}
      </div>
    </details>
  );
}
