"""Capture fresh OSV probes for the four native CVEs missed in the QA run.

Read-only diagnosis. Does not change the scanner or the independent answer key.
Exact submitted PURLs come from the saved scan responses. Alternative Git-tag
queries follow OSV's documented API and are recorded as separate experiments.
"""
import concurrent.futures
import datetime as dt
import json
from pathlib import Path
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'output/validation/root-cause-evidence'
DEST.mkdir(parents=True, exist_ok=True)
report = json.loads((ROOT/'output/validation/pandax-reference-comparison.json').read_text())
cases = [c for c in report['cases'] if c['id'].startswith(('curl-', 'openssl-'))]
targets = ['CVE-2023-38546','CVE-2023-46218','CVE-2014-0224','CVE-2014-0195']


def call(name, path, body=None):
    url='https://api.osv.dev/v1/'+path
    req=urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type':'application/json','User-Agent':'PandaX-independent-diagnosis/1'})
    result={'name':name,'url':url,'request':body,'checked_utc':dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result.update(http_status=resp.status,response=json.load(resp))
    except urllib.error.HTTPError as exc:
        result.update(http_status=exc.code,error=exc.read().decode())
    except Exception as exc:result['error']=repr(exc)
    (DEST/(name+'.json')).write_text(json.dumps(result,indent=2)+'\n')
    return result


def git_probe(case):
    curl=case['id'].startswith('curl-')
    repo='https://github.com/curl/curl.git' if curl else 'https://github.com/openssl/openssl.git'
    version=case['id'].split('-',1)[1]
    # Official tag spellings. These identify upstream sources, not distro packages.
    tag=('curl-'+version.replace('.','_')) if curl else ('OpenSSL_'+version.replace('.','_'))
    payload={'package':{'name':repo,'ecosystem':'GIT'},'version':tag}
    results=[]
    for page in range(10):
        result=call(case['id']+'-git-'+str(page+1),'query',payload)
        results.append(result)
        token=result.get('response',{}).get('next_page_token')
        if not token:break
        payload={**payload,'page_token':token}
    vulns=[v for r in results for v in r.get('response',{}).get('vulns',[])]
    ids={v['id'] for v in vulns}|{a for v in vulns for a in v.get('aliases',[])}
    return {'case':case['id'],'repo':repo,'tag':tag,'http_status':[r.get('http_status') for r in results],
            'record_count':len(vulns),'target_cves_found':sorted(ids.intersection(targets)),
            'pagination_complete':not results[-1].get('response',{}).get('next_page_token'),
            'errors':[r['error'] for r in results if r.get('error')]}


def main():
    purls=[]
    for c in cases:
        s=json.loads((ROOT/report['evidence_directory']/c['id']/'summary.json').read_text())
        purls.extend(x['purl'] for x in s['components'] if x['purl'])
    exact=call('exact-purl-replay','querybatch',{'queries':[{'package':{'purl':p}} for p in purls]})
    result={'purls':purls,'exact_query_file':'exact-purl-replay.json','exact_http_status':exact.get('http_status'),
            'exact_response':exact.get('response'),'git_probes':[],'direct_records':[]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for row in pool.map(git_probe,cases):
            result['git_probes'].append(row);print(json.dumps(row),flush=True)
    # Presence in OSV is independent of whether a specific package query matches.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        records=list(pool.map(lambda c:call(c,'vulns/'+c),targets))
    for row in records:
        d=row.get('response',{})
        result['direct_records'].append({'cve':row['name'],'http_status':row.get('http_status'),
                'packages':[x.get('package',{}) for x in d.get('affected',[])],
                'range_repositories':sorted({x.get('repo','') for a in d.get('affected',[]) for x in a.get('ranges',[]) if x.get('repo')})})
    (DEST/'diagnosis-summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':main()
