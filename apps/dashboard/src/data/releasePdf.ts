import type { Finding, Product, Release } from "./types";

export type ReleasePdfKind = "security" | "technical" | "declaration";

interface PdfSection { heading: string; lines: string[] }

const ascii = (value: unknown) => String(value ?? "Not recorded").replace(/[^\x20-\x7E]/g, "-");
const escaped = (value: string) => ascii(value).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
const label = (value: string) => value.replaceAll("_", " ");

function wrap(value: string, width = 88): string[] {
  const words = ascii(value).split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    if (line && `${line} ${word}`.length > width) { lines.push(line); line = ""; }
    let remaining = word;
    while (remaining.length > width) {
      lines.push(remaining.slice(0, width));
      remaining = remaining.slice(width);
    }
    if (remaining) line = line ? `${line} ${remaining}` : remaining;
  }
  if (line) lines.push(line);
  return lines.length ? lines : [""];
}

function findingsSection(findings: Finding[]): PdfSection {
  return {
    heading: `Findings and decisions (${findings.length})`,
    lines: findings.length ? findings.flatMap((finding, index) => [
      `${index + 1}. ${finding.reference} - ${finding.title}`,
      `Severity: ${finding.severity}; component: ${finding.component} ${finding.componentVersion}; status: ${label(finding.status)}`,
      `Reachability: ${label(finding.reachability)}; known exploited: ${finding.kev ? "yes" : "no"}`,
      `Decision: ${label(finding.decisions.at(-1)?.decision ?? "awaiting review")}`,
      `Reason: ${finding.decisions.at(-1)?.rationale ?? "No human decision recorded."}`,
      `Remediation: ${label(finding.remediation.status)}; target: ${finding.remediation.targetDate ?? finding.dueAt ?? "not set"}`,
      `Plan: ${finding.remediation.plan ?? "No remediation plan recorded."}`,
      "",
    ]) : ["No findings are recorded for this release."],
  };
}

function sections(kind: ReleasePdfKind, product: Product, release: Release, findings: Finding[]): PdfSection[] {
  const identity = {
    heading: "Product and release",
    lines: [
      `Product: ${product.name} (${product.identifier})`,
      `Manufacturer: ${product.manufacturer}`,
      `Release: ${release.version}; channel: ${release.channel}; date: ${release.releaseDate}`,
      `CRA classification recorded: ${label(product.craClass)}`,
      `SBOM: ${label(release.sbomStatus)}; identified components: ${release.coverage.identifiedComponents}/${release.coverage.components}`,
    ],
  };
  const coverage = {
    heading: "Coverage and limitations",
    lines: [
      `Advisory sources checked: ${release.coverage.advisorySourcesChecked}/${release.coverage.advisorySourcesExpected}`,
      `Monitoring: ${label(release.monitoringHealth)}`,
      ...(release.coverage.limitations.length ? release.coverage.limitations : ["No coverage limitations recorded."]),
      "An SBOM alone does not establish runtime reachability, product design, conformity, or manufacturer attestations.",
    ],
  };
  const legal = {
    heading: "Regulatory basis and review",
    lines: [
      "Regulation (EU) 2024/2847 (Cyber Resilience Act): Annex I sets essential product security and vulnerability-handling requirements; Article 13 sets manufacturer obligations.",
      "Article 14 requires notification of actively exploited vulnerabilities and severe incidents. An early warning is due within 24 hours and a notification within 72 hours of awareness; final-report deadlines depend on the event.",
      "Article 14 reporting applies from 11 September 2026. The main product requirements apply from 11 December 2027 (Article 71). This report does not submit a notification.",
      "Source: EUR-Lex, Regulation (EU) 2024/2847, https://eur-lex.europa.eu/eli/reg/2024/2847/oj",
    ],
  };
  if (kind === "security") return [identity, coverage, findingsSection(findings), {
    heading: "Document status",
    lines: ["Internal assessment draft. Decisions and remediation reflect the current browser state.", "Not a regulatory filing, conformity declaration, or certification."],
  }, legal];
  if (kind === "technical") return [identity, coverage, findingsSection(findings), {
    heading: "Annex VII documentation gaps",
    lines: ["Annex VII requires a product description and intended purpose; design, development, production and vulnerability-handling information; a cybersecurity risk assessment; applied standards or specifications; and test reports and other evidence.", "Manufacturer must supply and review those materials. This evidence summary is not complete technical documentation."],
  }, legal];
  return [identity, {
    heading: "Declaration status",
    lines: ["DRAFT - NOT ISSUED. No declaration of conformity is made by this document.", "Annex V sets the EU declaration content, including product identification, manufacturer's sole responsibility, applicable legislation, relevant standards or specifications, and signature details.", "Manufacturer identification, conformity assessment, responsible signature, place and date require review and attestation. Scan findings alone cannot establish conformity."],
  }, coverage, legal];
}

function makePdf(title: string, product: Product, release: Release, sectionsToDraw: PdfSection[]): Uint8Array {
  const encoder = new TextEncoder();
  const pages: string[][] = [[]];
  let y = 736;
  const write = (value: string, heading = false) => {
    if (y < 78) { pages.push([]); y = 736; }
    const safe = escaped(value);
    pages.at(-1)!.push(`BT /${heading ? "F2" : "F1"} ${heading ? 11 : 9} Tf 0 g 56 ${y} Td (${safe}) Tj ET`);
    y -= heading ? 21 : 15;
  };
  write(title, true);
  write(`${product.name} | ${release.version}`);
  write(`Prepared ${new Date().toISOString().slice(0, 10)} | Internal working draft`);
  y -= 17;
  for (const section of sectionsToDraw) {
    if (y < 110) { pages.push([]); y = 736; }
    write(section.heading, true);
    for (const line of section.lines) {
      for (const part of wrap(line)) write(part);
    }
    y -= 12;
  }
  const objects: string[] = ["", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"];
  const kids: string[] = [];
  pages.forEach((commands, index) => {
    const pageId = 5 + index * 2;
    const contentId = pageId + 1;
    kids.push(`${pageId} 0 R`);
    commands.unshift("0 G 0.5 w 56 782 m 539 782 l S", "BT /F2 8 Tf 0 g 56 794 Td (ACTIS  /  PRODUCT ASSURANCE) Tj ET");
    commands.push("0 G 0.5 w 56 57 m 539 57 l S", `BT /F1 8 Tf 0 g 56 43 Td (Internal draft  |  ${index + 1} / ${pages.length}) Tj ET`);
    const stream = commands.join("\n");
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentId} 0 R >>`);
    objects.push(`<< /Length ${encoder.encode(stream).length} >>\nstream\n${stream}\nendstream`);
  });
  objects[0] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[1] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${pages.length} >>`;
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((object, index) => { offsets.push(encoder.encode(pdf).length); pdf += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = encoder.encode(pdf).length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach((offset) => { pdf += `${offset.toString().padStart(10, "0")} 00000 n \n`; });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return encoder.encode(pdf);
}

export function createReleasePdf(kind: ReleasePdfKind, product: Product, release: Release, findings: Finding[]): Uint8Array {
  const title = kind === "security" ? "Product release security report" : kind === "technical" ? "Annex VII technical documentation - draft" : "EU Declaration of Conformity - draft";
  return makePdf(title, product, release, sections(kind, product, release, findings));
}
