"""PandaX internal fields mapped to ENISA glossary 1.1, not an SRP API."""
from .cases import CaseError
from .case_review import timestamp

SOURCE = 'https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2'
VERSION = 'enisa-1.1-2026-09-05/pandax-1'
RETRIEVED = '2026-09-08'
STAGES = ('early_warning', 'notification', 'final_report')
# R required, O optional, A required if available, X not applicable.
# Carried values retain provenance; a later stage still validates required values.
ROWS = [
    ('1', 'notification_type', 'Case type', 'both', 'RRR', 255),
    ('2', 'title', 'Title', 'both', 'RRR', 255),
    ('3', 'summary', 'Summary', 'both', 'RRR', 4000),
    ('4', 'manufacturer', 'Manufacturer', 'both', 'RRR', 255),
    ('5', 'member_states', 'Distribution countries', 'both', 'AAA', 255),
    ('6', 'product_name', 'Product', 'both', 'RRR', 255),
    ('7', 'product_version', 'Affected versions', 'both', 'RRR', 255),
    ('8', 'product_type', 'Regulatory type', 'both', 'OOO', 255),
    ('9', 'product_class', 'Product class', 'both', 'OOO', 255),
    ('10', 'product_category', 'Category', 'both', 'OOO', 255),
    ('11', 'end_of_support', 'Support ended', 'both', 'OOO', 255),
    ('12', 'component', 'Component', 'both', 'OOO', 255),
    ('13', 'measure_expected', 'Measure expected soon', 'both', 'OOO', 255),
    ('14', 'user_action', 'Immediate user action', 'both', 'OOO', 4000),
    ('15', 'sensitivity', 'Sensitivity justification', 'both', 'OAA', 255),
    ('16', 'measures_taken', 'Completed measures', 'both', 'ORR', 2000),
    ('17', 'user_measures', 'User mitigation instructions', 'both', 'ORR', 4000),
    ('18', 'attack_vector', 'Attack path', 'both', 'OOO', 255),
    ('v19', 'cve', 'CVE', 'vulnerability', 'OOO', 255),
    ('v20', 'euvd', 'EUVD', 'vulnerability', 'OOO', 255),
    ('v21', 'general_information', 'Vulnerability overview', 'vulnerability', 'ORR', 4000),
    ('v22', 'measure_available_at', 'Measure availability', 'vulnerability', 'OOR', 255),
    ('v23', 'severity_description', 'Severity analysis', 'vulnerability', 'OOR', 4000),
    ('v24', 'impact_description', 'Impact analysis', 'vulnerability', 'OOR', 4000),
    ('v25', 'aware_at', 'Awareness time', 'vulnerability', 'RRR', 255),
    ('v26', 'malicious_actor', 'Actor information', 'vulnerability', 'OOA', 100),
    ('v27', 'pec', 'Exceptional circumstances', 'vulnerability', 'XOX', 255),
    ('v28', 'pec_reason', 'Dissemination delay reason', 'vulnerability', 'XOX', 4000),
    ('v29', 'further_information', 'Additional information', 'vulnerability', 'OOO', 4000),
    ('i30', 'malicious_activity', 'Malicious activity suspected', 'incident', 'RRR', 255),
    ('i31', 'incident_nature', 'Incident overview', 'incident', 'ORR', 4000),
    ('i32', 'mitigation', 'Applied or ongoing mitigation', 'incident', 'OOR', 4000),
    ('i33', 'severity_description', 'Severity analysis', 'incident', 'OOR', 4000),
    ('i34', 'impact_description', 'Impact analysis', 'incident', 'OOR', 4000),
    ('i35', 'root_cause', 'Likely cause', 'incident', 'OOR', 255),
    ('i36', 'aware_at', 'Awareness time', 'incident', 'RRR', 255),
    ('i37', 'occurred_at', 'Occurrence time', 'incident', 'OOO', 255),
    ('i38', 'initial_assessment', 'Initial assessment', 'incident', 'ORR', 4000),
]
ENUMS = {'product_type': ['Default', 'Important', 'Critical'], 'end_of_support': ['Yes', 'No'], 'measure_expected': ['Yes', 'No', 'Unknown'], 'malicious_activity': ['Yes', 'No', 'Unknown'], 'notification_type': ['Vulnerability', 'Incident']}
FACTS = {'aware_at', 'occurred_at', 'measure_available_at', 'notification_type'}


def definitions(case_type, stage):
    if case_type not in ('vulnerability', 'incident') or stage not in STAGES:
        raise CaseError('unknown case type or reporting stage')
    index = STAGES.index(stage)
    return {'version': VERSION, 'source': SOURCE, 'retrieved_at': RETRIEVED, 'fields': [
        {'source_id': nr, 'key': key, 'label': label, 'requirement': {'R': 'required', 'O': 'optional', 'A': 'if_available'}[requirements[index]], 'max_length': limit, 'choices': ENUMS.get(key), 'factual': key in FACTS, 'carried_forward': index > 0 and key not in ('pec', 'pec_reason', 'attack_vector')}
        for nr, key, label, applies, requirements, limit in ROWS
        if applies in ('both', case_type) and requirements[index] != 'X'
    ]}


def fields_for(case, stage, supplied):
    definition = definitions(case['case_type'], stage)
    allowed = {f['key'] for f in definition['fields']}
    if set(supplied) - allowed:
        raise CaseError('unknown or inapplicable report fields: ' + ', '.join(sorted(set(supplied) - allowed)))
    previous = next((r for r in reversed(case['revisions']) if r['payload'].get('field_definition', {}).get('version') == VERSION), None)
    fields = {key: {**value, 'carried_from_revision': previous['revision']} for key, value in (previous['payload']['fields'].items() if previous else []) if key in allowed}
    seeded = {
        'notification_type': ('Incident' if case['case_type'] == 'incident' else 'Vulnerability', 'machine_derived'),
        'product_name': (case['source_product']['name'], 'machine_derived'),
        'product_version': (case['source_product']['version'], 'machine_derived'),
        'aware_at': (case['state'].get('aware_at'), 'operator_attested'),
        'occurred_at': (case['state'].get('occurred_at'), 'operator_attested'),
        'measure_available_at': (case.get('measure_available_at'), 'operator_attested'),
        'cve': (case.get('cve'), 'machine_derived'),
        'component': (case.get('component'), 'machine_derived'),
    }
    for key, (value, provenance) in seeded.items():
        if key in allowed and (key not in fields or key in FACTS):
            fields[key] = {'value': value, 'provenance': provenance if value else 'missing'}
    for key, value in supplied.items():
        entry = value if isinstance(value, dict) else {'value': value}
        if set(entry) - {'value', 'available'}:
            raise CaseError('field inputs accept only value and available; provenance is server-owned')
        if key in FACTS and entry.get('value') != seeded[key][0]:
            raise CaseError(f'{key} must be changed through its factual case action')
        if 'available' in entry and type(entry['available']) is not bool:
            raise CaseError('available must be true or false')
        if entry.get('value') is not None and not isinstance(entry['value'], str):
            raise CaseError('report field values must be strings or null')
        fields[key] = {**entry, 'provenance': 'operator_attested'}
    return definition, {key: fields.get(key, {'value': None, 'provenance': 'missing'}) for key in allowed}


def missing_fields(payload):
    definition = payload.get('field_definition')
    if not definition or definition.get('version') != VERSION:
        return ['prepare a report using the current field definitions']
    fields = payload['fields']
    missing = []
    for field in definitions(payload['case_type'], payload['stage'])['fields']:
        key = field['key']
        entry = fields.get(key, {})
        value = entry.get('value')
        present = isinstance(value, str) and bool(value.strip()) and not any(token in value.upper() for token in ('INPUT REQUIRED', 'MANUFACTURER INPUT', 'TODO', 'TBD', 'PLACEHOLDER'))
        required = field['requirement'] == 'required' or (field['requirement'] == 'if_available' and entry.get('available') is not False)
        if required and not present:
            missing.append(key + (' (provide value or attest unavailable)' if field['requirement'] == 'if_available' else ''))
        if present and (len(value) > field['max_length'] or (field['choices'] and value not in field['choices'])):
            missing.append(key + ' (invalid format)')
        if present and key.endswith('_at'):
            try:
                timestamp(value)
            except CaseError:
                missing.append(key + ' (timezone required)')
        if entry.get('available') is False and present:
            missing.append(key + ' (value conflicts with unavailable attestation)')
    if fields.get('pec', {}).get('value') and not fields.get('pec_reason', {}).get('value'):
        missing.append('pec_reason')
    if payload.get('case_facts', {}).get('reportability') != 'reportable':
        missing.append('reviewed reportability decision')
    return missing
