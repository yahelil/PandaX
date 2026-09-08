import datetime as dt

from pandax.case_service import CaseService
from pandax.case_workflow import clock_status
from test_case_service import service, create, measure
from test_case_review import command


def test_vulnerability_clocks_review_and_stages(service):
    case = create(service)
    assert case['deadlines'] == dict.fromkeys(('early_warning', 'notification', 'final_report'))
    assert 'reportability' not in case['state']
    case = command(service, case, 'record-awareness', aware_at='2026-09-15T03:00:00+03:00', evidence='Confirmed exploitation report')
    assert case['deadlines'] == {'early_warning': '2026-09-16T00:00:00Z', 'notification': '2026-09-18T00:00:00Z', 'final_report': None}
    due = dict(case['deadlines'])
    case = command(service, case, 'record-decision', reportability='reportable', evidence='Product applicability established', reason='Reviewed exploitation evidence')
    assert case['deadlines'] == due
    case = service.execute('confirm-measure', measure(case), case['id'])
    assert case['deadlines']['final_report'] == '2026-09-29T12:00:00Z'
    for stage in ('early_warning', 'notification', 'final_report'):
        case = command(service, case, 'prepare-report', stage=stage)
        assert case['report']['payload']['stage'] == stage
        assert not case['approved']
    final = case['deadlines']['final_report']
    case = command(service, case, 'record-awareness', aware_at='2026-09-14T00:00:00Z', evidence='Earlier email', reason='Correct factual date')
    assert case['deadlines']['early_warning'] == '2026-09-15T00:00:00Z'
    assert case['deadlines']['final_report'] == final
    assert any(e['event_type'] == 'clocks_updated' and e['payload']['previous'] == due for e in case['events'])
    assert CaseService(runs_dir=service.runs_dir).get(case['id']) == case
    assert clock_status({'early_warning': '2026-09-15T00:00:00Z', 'notification': None}, dt.datetime(2026, 9, 16, tzinfo=dt.timezone.utc)) == {'early_warning': 'overdue', 'notification': 'pending'}
