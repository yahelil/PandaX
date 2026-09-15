"""Build the observed-results PDF; the independent baseline PDF is untouched."""
import json
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import A4

ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/'workspace/generated/validation/pandax-reference-comparison.json'
if not REPORT.exists(): REPORT=ROOT/'docs/published/validation/pandax-reference-comparison.json'
R=json.loads(REPORT.read_text())
B=json.loads((ROOT/'docs/expected-results-baseline.json').read_text())
S={s['id']:s for s in B['sources']}
NAVY=colors.HexColor('#17324D'); TEAL=colors.HexColor('#087F72'); RED=colors.HexColor('#B52B3C')
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='Title2',fontSize=25,leading=29,textColor=NAVY,spaceAfter=18))
styles.add(ParagraphStyle(name='Small2',fontSize=8,leading=11,spaceAfter=6))
styles.add(ParagraphStyle(name='Body2',fontSize=10,leading=14,spaceAfter=10))
styles.add(ParagraphStyle(name='Cell2',fontSize=8,leading=11))
styles.add(ParagraphStyle(name='Head2',fontSize=14,leading=18,textColor=NAVY,spaceAfter=10))

def p(t,style='Body2'):return Paragraph(escape(str(t)),styles[style])
def table(rows,widths):
 t=Table([[p(c,'Cell2') for c in row] for row in rows],colWidths=widths,repeatRows=1,hAlign='LEFT')
 t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#E6EEF5')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('LINEBELOW',(0,0),(-1,0),1,NAVY),('LINEBELOW',(0,1),(-1,-1),.35,colors.HexColor('#D5DEE5'))]))
 return t

def footer(c,d):
 c.setStrokeColor(TEAL);c.line(42,39,553,39);c.setFont('Helvetica',8);c.setFillColor(NAVY)
 c.drawString(42,26,'PandaX | Independent comparison | 07 September 2026');c.drawRightString(553,26,str(d.page))

story=[p('PandaX\nDeveloper validation report'.replace('\n',' '),'Title2'),p('69 of 76 named checks matched. Seven expected findings were missed.','Head2'),p('14 input scans completed; all 14 seals verified. Four built-in comparison actions passed. Positive checks: 35/42 found. Negative checks: 34/34 correctly absent.'),p('Scope: the freshly pulled local dashboard at engine revision d7f7890, tested through its HTTP endpoints on 7 September 2026. A separate hosted deployment was not verified. No exploit or runtime reachability testing was performed.'),p('How to read this report','Head2'),p('HIT = expected vulnerable component/CVE was found. MISS = expected finding was absent. CORRECT ABSENCE = selected fixed or excluded CVE was absent. UNGRADED = an additional reported CVE outside the selected answer key; it is not automatically a false positive.'),p('The companion Independent Expected Results PDF is the frozen, online-source answer key. This document adds observed output. The ZIP includes every reported finding, raw evidence and the detailed root-cause report.'),table([['Result','Count'],['Expected affected-library findings found','35 / 42'],['Expected affected-library findings missed','7 / 42'],['Named negative controls correctly absent','34 / 34'],['Total observed component/CVE rows','407'],['Execution failures','0 / 14']], [350,161]),Spacer(1,18),p('Passing the built-in demo checks does not establish complete vulnerability coverage. The reference is a selected acceptance set, not an exhaustive CVE catalog.','Small2'),PageBreak(),p('Why the misses happened','Title2'),p('Inventory succeeded; vulnerability discovery was incomplete.','Head2'),p('The exact generic package identifiers for curl/libcurl and OpenSSL/libssl returned no candidates from OSV. PandaX then supplemented only the original SOCKS5 and Heartbleed demo CVEs. It has no native rules for the four missed CVEs.'),table([['Affected releases','Missing CVE','Vendor fix'],['libcurl 8.3.0','CVE-2023-38546','8.4.0'],['libcurl 8.3.0 and 8.4.0','CVE-2023-46218','8.5.0'],['libssl 1.0.1f and 1.0.1g','CVE-2014-0224','1.0.1h'],['libssl 1.0.1f and 1.0.1g','CVE-2014-0195','1.0.1h']],[232,170,109]),Spacer(1,14),p('What the diagnostic requests proved','Head2'),p('All four CVEs exist in OSV. Git-tag queries discovered the two curl CVEs, but not the two OpenSSL CVEs. The direct OpenSSL records contain no affected-package/range entries. There is no evidence that triage suppressed returned findings.'),p('A fallback also needs conflict handling: OSV lists curl 8.4.0 as affected by CVE-2023-38546, contrary to the vendor-fixed boundary. The diagnostic Git result is not an original PandaX false positive.'),p('Developer priorities','Head2'),p('1. Add source-aware native discovery and vendor fix evidence.\n2. Distinguish no returned candidates from established coverage.\n3. Preserve negative controls when resolving feed conflicts.\n4. Separate affected-library status from proven exploitability.\n5. Keep the independent acceptance tests outside the demo rules.'),p('See reports/PandaX_Root_Cause_Report.md and raw root-cause-evidence JSON for requests, responses and source-code locations. No scanner fix was applied in this investigation.','Small2')]
for case in R['cases']:
 story += [PageBreak(),p(case['title'],'Title2')]
 pos=[x for x in case['checks'] if x['expected']=='find']; neg=[x for x in case['checks'] if x['expected']!='find']
 hit=sum(x['verdict']=='MATCH' for x in pos); absent=sum(x['verdict']=='MATCH' for x in neg)
 story += [p(f"HITS {hit}/{len(pos)}   |   CORRECT ABSENCES {absent}/{len(neg)}   |   REPORTED ROWS {case['stats']['findings']}",'Head2'),p('Scan completed and seal verified. All selected expected inventory entries were present.','Small2')]
 rows=[['Component / CVE','Expected','Observed','Result']]
 for ch in case['checks']:
  verdict='HIT' if ch['expected']=='find' and ch['verdict']=='MATCH' else 'CORRECT ABSENCE' if ch['verdict']=='MATCH' else 'MISS' if ch['verdict']=='MISSING_FINDING' else ch['verdict']
  rows.append([ch['component']+'\n'+ch['cve'],{'find':'Affected','fixed':'Fixed','excluded':'Excluded'}.get(ch['expected'],ch['expected']),ch['observed'].replace('_',' '),verdict])
 story += [table(rows,[187,85,108,131]),Spacer(1,14),p('Applicability and comparison notes','Head2')]
 for ch in case['checks']:
  story.append(p(ch['cve']+': '+ch['reason'],'Small2'))
 if case['id'].startswith('smarthub'):
  story.append(p('Triage discrepancy: Pillow/WebP build evidence is missing, but VEX asserts exploitable from KEV. This is unsupported certainty, not a proven false positive.','Small2'))
 if case['id']=='openssl-1.0.1f':story.append(p('Triage discrepancy: Heartbleed VEX says exploitable while its explanation says build flags and runtime reachability remain unknown.','Small2'))
 story.append(p('All reported findings (including ungraded extras): cases/'+case['id']+'/all-findings.csv. Raw SBOM, findings, VEX and signed output files are in evidence/bundles/'+case['run_id']+'/ in the ZIP.','Small2'))
 links=[]
 for sid in dict.fromkeys(ch['source'] for ch in case['checks']):
  src=S[sid];links.append('<link href="'+escape(src['url'],{'"':'&quot;'})+'" color="#087F72">'+escape(sid)+'</link>')
 story.append(Paragraph('Public sources (click IDs; full titles in the independent PDF): '+', '.join(links),styles['Small2']))
output=ROOT/'workspace/generated/pdf/PandaX_Developer_Validation_Report.pdf'
output.parent.mkdir(parents=True,exist_ok=True)
SimpleDocTemplate(str(output),pagesize=A4,leftMargin=42,rightMargin=42,topMargin=42,bottomMargin=52,title='PandaX Developer Validation Report',author='PandaX validation review').build(story,onFirstPage=footer,onLaterPages=footer)
print(output)
