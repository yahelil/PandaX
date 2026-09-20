import { Check, Copy, Download, ShieldCheck, Terminal } from "lucide-react";
import { useState } from "react";

export const COLLECTOR_DOWNLOAD_URL = "https://github.com/yahelil/PandaX/releases/latest/download/actis-collector-windows-x64.zip";
export const COLLECTOR_SBOM_COMMAND = '.\\actis-collector.exe sbom "C:\\path\\to\\product" --output ".\\bom.cdx.json"';

export function LocalSbomGuide({ compact = false }: { compact?: boolean }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [open, setOpen] = useState(false);
  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(COLLECTOR_SBOM_COMMAND);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };

  return <details className={`local-sbom-guide${compact ? " local-sbom-guide--compact" : ""}`} onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary>
      <span className="local-sbom-guide__icon" aria-hidden="true"><ShieldCheck size={20} /></span>
      <span><strong>Generate an SBOM locally</strong><small>Keep source code on your computer, then upload only the generated JSON.</small></span>
      <span className="local-sbom-guide__show">{open ? "Hide steps" : "Show steps"}</span>
    </summary>
    <div className="local-sbom-guide__body">
      <ol>
        <li><a className="button" href={COLLECTOR_DOWNLOAD_URL} target="_blank" rel="noreferrer"><Download size={16} /> Download Windows x64 tool</a></li>
        <li>Extract the ZIP and open PowerShell in the <code>actis-collector</code> folder.</li>
        <li>Run this command, replacing the example path with your product directory or archive:</li>
      </ol>
      <div className="local-command">
        <Terminal size={17} aria-hidden="true" />
        <code>{COLLECTOR_SBOM_COMMAND}</code>
        <button type="button" onClick={copyCommand} aria-label="Copy local SBOM command">{copyState === "copied" ? <Check size={16} /> : <Copy size={16} />} {copyState === "copied" ? "Copied" : "Copy"}</button>
      </div>
      <p className="local-sbom-guide__privacy"><ShieldCheck size={16} aria-hidden="true" /><span><strong>Nothing is uploaded while the tool runs.</strong> Your source stays local. Actis receives only <code>bom.cdx.json</code> if you choose to upload it.</span></p>
      {copyState === "failed" ? <p className="danger-text" role="alert">Clipboard access was blocked. Select the command and copy it manually.</p> : null}
    </div>
  </details>;
}
