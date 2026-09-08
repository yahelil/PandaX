"""Case HTTP adapter. All mutations use the same service as the CLI."""
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from .case_service import CaseService
from .cases import CaseError, CaseConflict, CaseNotFound

router = APIRouter()


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


@router.get('/api/cases')
def list_cases():
    return call(lambda: service().list())


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
