"""Case HTTP adapter. All mutations use the same service as the CLI."""
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, Response

from .case_service import CaseService
from .cases import CaseError, CaseConflict, CaseNotFound

router = APIRouter()


@router.get('/api/case-fields/{case_type}/{stage}')
def fields(case_type: str, stage: str):
    from .case_fields import definitions
    return call(lambda: definitions(case_type, stage))


@router.get('/api/cases/{case_id}/snapshots/{snapshot_id}')
def download_snapshot(case_id: str, snapshot_id: str):
    from .case_snapshot import snapshot_bytes
    content = call(lambda: snapshot_bytes(service(), case_id, snapshot_id))
    return Response(content, media_type='application/zip', headers={'Content-Disposition': 'attachment; filename="case-snapshot.zip"'})


@router.get('/api/cases/{case_id}/receipts/{receipt_id}')
def download_receipt(case_id: str, receipt_id: str):
    def read():
        import hashlib
        with service().store._connect() as db:
            row = db.execute('SELECT r.content, r.sha256 FROM receipts r JOIN submissions s ON r.submission_id=s.id WHERE r.id=? AND s.case_id=?', (receipt_id, case_id)).fetchone()
            if not row:
                raise CaseNotFound('receipt not found')
            if hashlib.sha256(row['content']).hexdigest() != row['sha256']:
                raise CaseError('receipt digest mismatch')
            return row['content']
    return Response(call(read), media_type='application/octet-stream', headers={'Content-Disposition': 'attachment; filename="receipt.bin"'})


@router.get('/api/cases/{case_id}/export')
def export(case_id: str, revision: int | None = None, format: str = 'json'):
    from .case_export import render
    content = call(lambda: render(service().get(case_id), revision, format))
    return Response(content, media_type={'json': 'application/json', 'html': 'text/html', 'checklist': 'text/plain'}[format])


def service():
    from . import server
    return CaseService(runs_dir=server.OUT_DIR)


def call(operation):
    try:
        return operation()
    except CaseNotFound as exc:
        raise HTTPException(404, str(exc)) from exc
    except CaseConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except CaseError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get('/cases.js')
def javascript():
    return FileResponse(Path(__file__).parent / 'web' / 'cases.js', media_type='text/javascript')


@router.get('/cases.css')
def stylesheet():
    return FileResponse(Path(__file__).parent / 'web' / 'cases.css', media_type='text/css')


@router.get('/api/cases')
def list_cases():
    return call(lambda: service().list())


def advisory_service():
    from .advisory_watch import AdvisoryWatchService
    return AdvisoryWatchService(service())


@router.get('/api/advisory-watches')
def list_advisory_watches():
    return call(lambda: advisory_service().list())


@router.post('/api/advisory-watches')
def create_advisory_watch(body: dict):
    return call(lambda: advisory_service().watch(body.get('source_run_id', ''), body.get('simulated', False)))


@router.post('/api/advisory-watches/refresh')
def refresh_advisory_watches(body: dict):
    def refresh():
        watch_id = body.get('watch_id')
        replay = body.get('replay')
        if replay is not None:
            return advisory_service().refresh(watch_id, replay)
        from . import server
        loop = getattr(server.api.state, 'advisory_refresh', None)
        return loop.refresh_now() if loop and not watch_id else advisory_service().refresh(watch_id)
    return call(refresh)


@router.post('/api/cases')
def create(body: dict):
    return call(lambda: service().execute('create', body))


@router.post('/api/cases/import-draft')
def import_draft(body: dict):
    return call(lambda: service().execute('import-draft', body))


@router.post('/api/cases/create-incident')
def incident(body: dict):
    return call(lambda: service().execute('create-incident', body))


@router.get('/api/cases/{case_id}')
def detail(case_id: str):
    return call(lambda: service().get(case_id))


@router.get('/api/cases/{case_id}/report')
def report(case_id: str):
    case = call(lambda: service().get(case_id))
    if not case['report']:
        raise HTTPException(409, 'no report revision yet')
    return case['report']


@router.post('/api/cases/{case_id}/{action}')
def mutate(case_id: str, action: str, body: dict):
    return call(lambda: service().execute(action, body, case_id))
