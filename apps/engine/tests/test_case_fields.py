import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pandax.case_fields import definitions, ROWS, missing_fields
from pandax.case_export import pack, render
from pandax.cases import CaseError
from test_case_service import service, create, measure
from test_case_review import command
from test_case_incident import incident


def ready_case(service, case_type='vulnerability', stage='early_warning'):
    case = incident(service) if case_type == 'incident' else create(service)
    case = command(service, case, 'record-awareness', aware_at='2026-09-15T00:00:00Z', evidence='Verified timeline')
    case = command(service, case, 'record-decision', reportability='reportable', reason='Reviewed', evidence='Evidence')
    if case_type == 'vulnerability':
        case = service.execute('confirm-measure', measure(case), case['id'])
    case = command(service, case, 'prepare-report', stage=stage)
    fields = {}
    for field in definitions(case_type, stage)['fields']:
        if field['factual']:
            continue
        if field['requirement'] == 'required':
            fields[field['key']] = field['choices'][0] if field['choices'] else 'Verified manufacturer information'
        elif field['requirement'] == 'if_available':
            fields[field['key']] = {'value': None, 'available': False}
    case = command(service, case, 'prepare-report', stage=stage, fields=fields)
    return command(service, case, 'approve', revision=case['report']['revision'], report_hash=case['report']['report_hash'], approved_at='2026-09-15T01:00:00Z')


@pytest.mark.parametrize('case_type', ['vulnerability', 'incident'])
@pytest.mark.parametrize('stage', ['early_warning', 'notification', 'final_report'])
def test_all_stage_packs(service, case_type, stage):
    case = ready_case(service, case_type, stage)
    assert pack(case)['ready'], pack(case)['missing']
    assert not missing_fields(case['report']['payload'])
    assert 'manual submission' in render(case, format='html')
    assert '[ ]' in render(case, format='checklist')
    assert json.loads(render(case))['report_hash'] == case['report']['report_hash']
    assert len(ROWS) == 38


def test_conditional_placeholders_and_carry_forward(service):
    case = ready_case(service)
    approved = case['report']['revision']
    case = command(service, case, 'prepare-report', stage='notification', fields={'measures_taken': 'INPUT REQUIRED', 'user_measures': 'Use isolation', 'general_information': 'Details'})
    assert 'measures_taken' in case['readiness']['missing']
    assert not case['readiness']['ready']
    assert not pack(case, approved)['ready']
    assert case['report']['payload']['fields']['manufacturer']['carried_from_revision'] == approved
    case = command(service, case, 'revise', payload={'measures_taken': '<script>alert(1)</script>', 'sensitivity': {'value': None, 'available': False}}, reason='Completed')
    assert not missing_fields(case['report']['payload'])
    assert '&lt;script&gt;' in render(case, format='html')
    assert '<script>' not in render(case, format='html')
    with pytest.raises(CaseError, match='factual'):
        command(service, case, 'prepare-report', stage='early_warning', fields={'aware_at': '2027-01-01T00:00:00Z'})
    with pytest.raises(CaseError, match='provenance'):
        command(service, case, 'prepare-report', stage='early_warning', fields={'title': {'value': 'x', 'provenance': 'machine_derived'}})


def test_export_api_cli_parity(service, tmp_path):
    from pandax.server import api
    from pandax.cli import app
    case = ready_case(service)
    client = TestClient(api)
    response = client.get(f"/api/cases/{case['id']}/export")
    assert response.status_code == 200
    result = CliRunner().invoke(app, ['case', 'export', case['id']])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == response.json()
    assert client.get(f"/api/cases/{case['id']}/export?format=html").headers['content-type'].startswith('text/html')
    assert client.get(f"/api/cases/{case['id']}/export?format=bad").status_code == 422
    assert client.get('/api/case-fields/incident/notification').status_code == 200


def test_glossary_stage_requirements_are_not_conflated():
    def required_keys(kind, stage):
        return {f['key'] for f in definitions(kind, stage)['fields'] if f['requirement'] == 'required'}
    common = {'notification_type', 'title', 'summary', 'manufacturer', 'product_name', 'product_version', 'aware_at'}
    assert required_keys('vulnerability', 'early_warning') == common
    assert required_keys('incident', 'early_warning') == common | {'malicious_activity'}
    assert required_keys('vulnerability', 'final_report') == common | {'measures_taken', 'user_measures', 'general_information', 'measure_available_at', 'severity_description', 'impact_description'}
    assert required_keys('incident', 'final_report') == common | {'malicious_activity', 'measures_taken', 'user_measures', 'incident_nature', 'mitigation', 'severity_description', 'impact_description', 'root_cause', 'initial_assessment'}
