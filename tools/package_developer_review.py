"""Export portable QA evidence, excluding vendor input/extracted trees and secrets.

Uses saved results only; does not run PandaX or alter its independent baseline.
Run after the two PDF builders. Requires the original local out/ run directories.
"""
import csv
import hashlib
import html
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
R=json.loads((ROOT/'output/validation/pandax-reference-comparison.json').read_text())
B=json.loads((ROOT/'docs/expected-results-baseline.json').read_text())
S={s['id']:s for s in B['sources']}
NAME='PandaX_Developer_Review_2026-09-07'
DEST=ROOT/'output/share';DEST.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

VERIFY='''"""Verify exported file hashes. Optional --signatures requires cryptography.
This is a partial output export; omitted input/extracted trees are not verified.
"""
import hashlib,json,sys
from pathlib import Path
root=Path(__file__).resolve().parent
m=json.loads((root/'SHA256SUMS.json').read_text())
for name,want in m.items():
 p=root/name
 if not p.is_relative_to(root) or not p.is_file():raise SystemExit('Missing: '+name)
 if hashlib.sha256(p.read_bytes()).hexdigest()!=want:raise SystemExit('Changed: '+name)
print(f'PASS: {len(m)} exported files match SHA-256 manifest.')
if '--signatures' in sys.argv:
 from cryptography.hazmat.primitives.serialization import load_pem_public_key
 for p in sorted((root/'evidence/bundles').iterdir()):
  manifest=json.loads((p/'manifest.json').read_text())
  canonical=json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
  load_pem_public_key((p/'pubkey.pem').read_bytes()).verify(bytes.fromhex((p/'manifest.sig').read_text().strip()),canonical)
  for item in manifest['files']:
   f=p/item['path']
   if f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest()!=item['sha256']:raise SystemExit('Signed file changed: '+str(f))
 print('PASS: all original manifest signatures and included signed file hashes verify.')
print('Vendor input/extracted trees are intentionally omitted. This is not full pandax verify. Local demo signatures prove integrity, not independent certification.')
'''


def write(p,s):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s,encoding='utf-8')
def copy(src,dst):dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
def csv_write(path,rows,columns):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=columns,lineterminator='\n',extrasaction='ignore');w.writeheader()
  for row in rows:w.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in row.items()})
def page(title,content):
 return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>'+html.escape(title)+'</title><style>body{font:16px/1.55 system-ui,sans-serif;max-width:1150px;margin:40px auto;padding:0 24px;color:#17324d;background:#f8fafc}h1{font-size:36px}a{color:#087f72}table{border-collapse:collapse;width:100%;background:white}th,td{padding:12px;text-align:left;border-bottom:1px solid #d5dee5;vertical-align:top}th{background:#e6eef5}.MISS{color:#b52b3c;font-weight:bold}.HIT{color:#087f72;font-weight:bold}small{color:#596775}code{overflow-wrap:anywhere}li{margin:6px 0}</style><h1>'+html.escape(title)+'</h1>'+content+'</html>'


def main():
 with tempfile.TemporaryDirectory(prefix='pandax-developer-package-') as tmp:
  base=Path(tmp)/NAME;base.mkdir()
  for fn in ['PandaX_Independent_Expected_Results.pdf','PandaX_Developer_Validation_Report.pdf']:copy(ROOT/'output/pdf'/fn,base/'pdf'/fn)
  copy(ROOT/'docs/expected-results-baseline.json',base/'reference/expected-results-baseline.json')
  copy(ROOT/R['evidence_directory']/'frozen-reference.json',base/'reference/frozen-reference.json')
  assert sha(base/'reference/expected-results-baseline.json')==R['reference_sha256']
  assert sha(base/'pdf/PandaX_Independent_Expected_Results.pdf')==R['reference_pdf_sha256']
  for fn in ['pandax-reference-comparison.csv','pandax-reference-comparison.json','PandaX_Root_Cause_Report.md']:copy(ROOT/'output/validation'/fn,base/'reports'/fn)
  report=(ROOT/'output/validation/PandaX_Comparison_Report.md').read_text()
  report=report.replace('../../docs/expected-results-baseline.json','../reference/expected-results-baseline.json')
  for c in R['comparisons']:
   report=report.replace('http://127.0.0.1:8000/api/run/'+c['run_id']+'/summary','../evidence/api/comparison-'+c['id']+'/summary.json')
  report += '\n\n## Portable developer export\n\nThis ZIP now includes saved API responses and original output artifacts under `evidence/`; see START_HERE.md for export limits and verification. The earlier local-storage paragraph describes the original repository report.\n'
  write(base/'reports/PandaX_Comparison_Report.md',report)
  shutil.copytree(ROOT/'output/validation/root-cause-evidence',base/'reports/root-cause-evidence')
  shutil.copytree(ROOT/R['evidence_directory'],base/'evidence/api')
  run_ids={c['run_id'] for c in R['cases']+R['comparisons']}
  for c in R['comparisons']:run_ids.update(x['run_id'] for x in c['comparison']['runs'])
  exports=[]
  for rid in sorted(run_ids):
   src=ROOT/'out'/rid;manifest=json.loads((src/'manifest.json').read_text())
   included=[]
   for f in sorted(src.rglob('*')):
    rel=f.relative_to(src)
    if f.is_file() and rel.parts[0] not in {'input','extracted'}:
     copy(f,base/'evidence/bundles'/rid/rel);included.append(str(rel))
   omitted=[x for x in manifest['files'] if x['path'] not in included]
   assert all(x['path'].startswith(('input/','extracted/')) for x in omitted),omitted[:3]
   exports.append({'run_id':rid,'manifest_sha256':sha(src/'manifest.json'),'included_files':included,'omitted_manifest_entries':omitted,'scope':'Original output files including filings; input/extracted vendor trees omitted.'})
  write(base/'evidence/export-map.json',json.dumps(exports,indent=2)+'\n')
  all_checks=[];all_findings=[];summary=[];home_rows=[]
  for c in R['cases']:
   cid=c['id'];case_dir=base/'cases'/cid;checks=[]
   for x in c['checks']:
    result='HIT' if x['verdict']=='MATCH' and x['expected']=='find' else 'CORRECT ABSENCE' if x['verdict']=='MATCH' else 'MISS' if x['verdict']=='MISSING_FINDING' else x['verdict']
    checks.append(dict(input=cid,component=x['component'],cve=x['cve'],name=x['name'],expected=x['expected'],observed=x['observed'],result=result,fix=x['fix'],applicability=x['reason'],source_url=S[x['source']]['url'],run_id=c['run_id']))
   all_checks+=checks
   findings=json.loads((ROOT/'out'/c['run_id']/'findings.json').read_text())
   assert len(findings)==c['stats']['findings']
   matched={(r['cve'],r['purl']) for x in c['checks'] for r in x['matched_rows']}
   fr=[dict(input=cid,baseline_grade='NAMED HIT' if (f['cve'],f['purl']) in matched else 'UNGRADED EXTRA',**f) for f in findings]
   all_findings+=fr
   csv_write(case_dir/'reference-checks.csv',checks,list(checks[0]))
   csv_write(case_dir/'all-findings.csv',fr,['input','baseline_grade','component','version','cve','purl','osv_id','severity','fixed_version','kev','epss','source','source_url','summary','applicability'])
   write(case_dir/'result.json',json.dumps(c,indent=2)+'\n')
   hits=sum(x['result']=='HIT' for x in checks);miss=sum(x['result']=='MISS' for x in checks);neg=sum(x['result']=='CORRECT ABSENCE' for x in checks)
   summary.append(dict(input=cid,title=c['title'],hits=hits,misses=miss,correct_absences=neg,reported_rows=len(fr),scan_complete=c['complete'],seal_verified=c['seal_ok'],run_id=c['run_id']))
   intro=f'<p><b>{hits} hits | {miss} misses | {neg} correct absences | {len(fr)} reported rows</b></p><p>Scan completed; seal verified. Additional CVEs outside the answer key remain ungraded.</p>'
   intro+='<p><a href="../../index.html">All inputs</a> | <a href="all-findings.csv">Every reported finding (CSV)</a> | <a href="reference-checks.csv">Reference checks (CSV)</a> | <a href="../../evidence/bundles/'+c['run_id']+'/findings.cdx-vex.json">VEX</a> | <a href="../../evidence/bundles/'+c['run_id']+'/sbom.cdx.json">SBOM</a> | <a href="../../evidence/api/'+cid+'/summary.json">Raw API summary</a></p>'
   rows='<table><tr><th>CVE / component</th><th>Expected / observed</th><th>Result</th><th>Fix and applicability</th></tr>'
   for x in checks:
    rows+='<tr><td>'+html.escape(x['cve']+' / '+x['component'])+'</td><td>'+html.escape(x['expected']+' / '+x['observed'])+'</td><td class="'+x['result'].split()[0]+'">'+x['result']+'</td><td>'+html.escape(('Fix: '+x['fix']+'. ' if x['fix'] else '')+x['applicability'])+' <a href="'+html.escape(x['source_url'])+'">Source</a></td></tr>'
   write(case_dir/'index.html',page(c['title'],intro+rows+'</table>'))
   md='# '+c['title']+'\n\n'+f'{hits} hits; {miss} misses; {neg} correct absences; {len(fr)} reported component/CVE rows.\n\n| CVE | Expected | Observed | Result |\n|---|---|---|---|\n'
   md+='\n'.join('| '+ ' | '.join(x[k] for k in ['cve','expected','observed','result'])+' |' for x in checks)
   md+='\n\nSee index.html for applicability/source links, all-findings.csv for every reported row, and result.json for complete comparison details.\n'
   write(case_dir/'RESULTS.md',md)
   home_rows.append('<tr><td><a href="cases/'+cid+'/index.html">'+html.escape(c['title'])+'</a></td>'+''.join('<td>'+str(v)+'</td>' for v in [hits,miss,neg,len(fr)])+'</tr>')
  assert len(all_checks)==76 and len(all_findings)==407
  assert sum(x['result']=='MISS' for x in all_checks)==7
  csv_write(base/'reports/all-reference-checks.csv',all_checks,list(all_checks[0]))
  csv_write(base/'reports/missed-findings.csv',[x for x in all_checks if x['result']=='MISS'],list(all_checks[0]))
  csv_write(base/'reports/all-reported-findings.csv',all_findings,['input','baseline_grade','component','version','cve','purl','osv_id','severity','fixed_version','kev','epss','source','source_url','summary','applicability'])
  csv_write(base/'reports/release-summary.csv',summary,list(summary[0]))
  csv_write(base/'reference/public-sources.csv',B['sources'],['id','title','url'])
  # The exact tested engine and fixtures, not today's moving checkout.
  archive=subprocess.check_output(['git','archive',R['engine_commit'],'apps/engine','fixtures','pyproject.toml','uv.lock','README.md'],cwd=ROOT)
  with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
   for member in tar:
    if member.isfile():
     assert not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
     dest=base/'reproduction/tested-source'/member.name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(tar.extractfile(member).read())
  for fn in ['evaluate_reference.py','test_evaluate_reference.py','investigate_native_misses.py','build_expected_results_pdf.py','build_developer_review_pdf.py','package_developer_review.py']:copy(ROOT/'tools'/fn,base/'reproduction/tools'/fn)
  write(base/'reproduction/README.md','# Reproduce the run\n\nClone https://github.com/yahelil/PandaX and check out '+R['engine_commit']+'. Follow that revision\'s README to bootstrap the dashboard. The exact tested source and fixtures are also included here. Copy tools/evaluate_reference.py into the checkout tools/ directory, reference/expected-results-baseline.json to docs/, and the independent PDF to output/pdf/. The evaluator uses repository-relative paths; run it from that checkout, not directly from this ZIP.\n\nRun `python tools/evaluate_reference.py --base-url http://127.0.0.1:8000`. Exit 1 means named checks or executions failed; read the generated report. This observed run exited 1 for seven missing findings. Public feeds can change; the ZIP preserves this run and later diagnostic responses.\n\nThe root-cause probe expects output/validation/pandax-reference-comparison.json and the saved API evidence at the report\'s evidence_directory. Restore those from this ZIP before rerunning the probe. The package builder additionally requires all original local out/ bundles.\n')
  start='''# PandaX developer review - 7 September 2026

Open **index.html** for an offline, clickable overview. Start with **pdf/PandaX_Developer_Validation_Report.pdf** for observed results; use **pdf/PandaX_Independent_Expected_Results.pdf** as the independent online-source answer key.

- 14 inputs completed, all 14 seals verified; four built-in comparisons passed.
- 76 named checks: 35 hits, seven misses, 34 correct absences.
- All 407 reported component/CVE rows are included. Extra findings are ungraded, not assumed false positives.
- The four missed CVEs occur across seven release/CVE checks. Inventory was correct; exact OSV identifiers yielded no candidates and the native supplement lacks those CVE rules.
- Tested the pulled local dashboard at d7f7890. A separate hosted deployment was not verified. No exploit/runtime testing was performed. No scanner fix was applied during this validation or diagnosis.

## Where to look

| Location | Contents |
|---|---|
| reports/PandaX_Root_Cause_Report.md | Cause of every miss, source locations, API probes, feed conflict and developer priorities |
| reports/PandaX_Comparison_Report.md | Overall comparison, all inputs, triage discrepancies and test results |
| reports/all-reference-checks.csv | All 76 named expectations, observations, fix versions, applicability and source URLs |
| reports/missed-findings.csv | Seven misses, ready for issue tracking |
| reports/all-reported-findings.csv | All 407 reported rows, with named-hit/ungraded labels |
| cases/ | Per-input HTML, Markdown, CSV and JSON results |
| evidence/api/ | Original saved summaries, events and verify responses for 14 scans and four comparisons |
| evidence/bundles/ | Original output files for 14 scans, four comparisons and eight comparison child scans (26 bundles) |
| reports/root-cause-evidence/ | Timestamped fresh OSV diagnostic requests/responses; separate from original scan results |
| reference/ | Frozen public-source baseline and source register |
| reproduction/ | Exact tested source, fixtures and runner/probe/build scripts |

## Evidence scope and integrity

Output files are copied byte-for-byte, including original manifest/signature/public key, SBOM, findings, VEX, ledger and automatic PoC PDFs. Vendor source archives and extracted trees are omitted to keep this package shareable; their hashes remain in the original manifests and evidence/export-map.json lists omissions. Private signing keys, credentials, caches and Git metadata are excluded.

Run `python3 verify_package.py` after extracting to verify all exported file hashes. For original manifest signatures and included signed output hashes, install `cryptography` and run `python3 verify_package.py --signatures`. This is **not full pandax verify** because vendor inputs are omitted. Original full verification responses are preserved. Demo signatures demonstrate integrity, not external certification or factual completeness.

Automatic Annex VII / Declaration PDFs inside bundles are unreviewed PoC outputs, not the independent answer key or an approved compliance declaration. Raw evidence retains historical local paths/URLs for integrity; use the portable index and case links to navigate offline. Public advisory links need internet access. The package checksum detects file changes; it is not an independent attestation.
'''
  write(base/'START_HERE.md',start)
  intro='<p><b>69 / 76 named checks matched. Seven expected findings missed.</b></p><p>14 scans completed and seals verified. Four built-in comparisons passed. Read the selected-check scope and evidence export limits in <a href="START_HERE.md">START_HERE.md</a>.</p><ul><li><a href="pdf/PandaX_Developer_Validation_Report.pdf">Results PDF</a> and <a href="pdf/PandaX_Independent_Expected_Results.pdf">independent expected-results PDF</a></li><li><a href="reports/PandaX_Root_Cause_Report.md">Why each miss happened and developer actions</a></li><li><a href="reports/missed-findings.csv">Seven misses</a> | <a href="reports/all-reference-checks.csv">All 76 checks</a> | <a href="reports/all-reported-findings.csv">All 407 reported rows</a></li></ul>'
  write(base/'index.html',page('PandaX developer review',intro+'<table><tr><th>Input / release</th><th>Hits</th><th>Misses</th><th>Correct absences</th><th>Reported rows</th></tr>'+''.join(home_rows)+'</table><p>Extra findings are ungraded. Absence of a named CVE does not establish whole-release security. Full diagnosis and applicability notes are included.</p>'))
  write(base/'verify_package.py',VERIFY)
  write(base/'PACKAGE_METADATA.json',json.dumps({'tested_engine_commit':R['engine_commit'],'started_utc':R['started_utc'],'finished_utc':R['finished_utc'],'reference_sha256':R['reference_sha256'],'independent_pdf_sha256':R['reference_pdf_sha256'],'inputs':14,'checks':76,'hits':35,'misses':7,'correct_absences':34,'reported_finding_rows':407,'output_bundles':len(run_ids),'vendor_input_trees_included':False},indent=2)+'\n')
  hashes={str(f.relative_to(base)):sha(f) for f in sorted(base.rglob('*')) if f.is_file()}
  write(base/'SHA256SUMS.json',json.dumps(hashes,indent=2)+'\n')
  subprocess.run([str(ROOT/'.venv/bin/python'),str(base/'verify_package.py'),'--signatures'],check=True)
  dest=DEST/(NAME+'.zip')
  with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
   for f in sorted(base.rglob('*')):
    if f.is_file():z.write(f,str(f.relative_to(base.parent)))
  with zipfile.ZipFile(dest) as z:assert z.testzip() is None
  write(DEST/(NAME+'.sha256'),sha(dest)+'  '+dest.name+'\n')
  print(json.dumps({'zip':str(dest),'bytes':dest.stat().st_size,'files':len(hashes)+1,'sha256':sha(dest)},indent=2))

if __name__=='__main__':main()
