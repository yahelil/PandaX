import pytest

from pandax.case_service import CaseService
from pandax.case_workflow import clocks
from pandax.cases import CaseError
from test_case_service import service, create, measure
from test_case_review import command, IDENTITY


def incident(service, request_id='incident'):
    return service.execute('create-incident', {'request_id': request_id, **IDENTITY, 'title': 'Service outage', 'severity': 'Severe', 'impact': 'Loss of authentication', 'product_name': 'Device', 'product_version': '1'})


def test_incident_without_scan_and_coexisting_cases(service):
    vulnerability = create(service)
    case = incident(service)
    second = incident(service, 'another')
    assert second['id'] != case['id']
    assert case['cve'] is None
    assert case['source_run_id'] == ''
    assert case['source_product']['name'] == 'Device'
    assert len(service.list()) == 3
    with pytest.raises(CaseError, match='vulnerability operation'):
        service.execute('confirm-measure', measure(case), case['id'])
    case = command(service, case, 'record-awareness', aware_at='2026-01-30T10:00:00Z', evidence='Incident timeline')
    assert case['deadlines']['final_report'] is None
    case = command(service, case, 'assess-incident', severity='Severe', impact='Access lost', mitigation='Isolated', root_cause='Credential compromise', evidence='Logs', reason='Incident review')
    case = command(service, case, 'record-decision', reportability='reportable', evidence='Service impact confirmed', reason='Severe impact')
    for stage in ('early_warning', 'notification', 'final_report'):
        case = command(service, case, 'prepare-report', stage=stage)
        assert case['report']['payload']['case_type'] == 'incident'
    assert CaseService(runs_dir=service.runs_dir).get(case['id']) == case
    assert service.get(vulnerability['id'])['case_type'] == 'vulnerability'


@pytest.mark.parametrize('submitted,expected', [
    ('2028-01-31T12:00:00Z', '2028-02-29T12:00:00Z'),
    ('2027-01-31T12:00:00Z', '2027-02-28T12:00:00Z'),
    ('2026-12-31T23:00:00Z', '2027-01-31T23:00:00Z'),
])
def test_incident_calendar_month(submitted, expected):
    assert clocks({'case_type': 'incident', 'measure_available_at': '2020-01-01T00:00:00Z'}, {'notification_submitted_at': submitted})['final_report'] == expected
