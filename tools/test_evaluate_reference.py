from evaluate_reference import compare_case


def case(expected='find'):
    return {'inventory': [{'name': 'libcurl', 'version': '8.3.0', 'aliases': ['libcurl']}],
            'checks': [{'component': 'libcurl', 'cve': 'CVE-2023-38545', 'expected': expected}]}


def summary(found=False, version='8.3.0'):
    return {'components': [{'name': 'libcurl', 'version': version}],
            'findings': [{'component': 'libcurl', 'version': version, 'cve': 'CVE-2023-38545'}] if found else []}


def test_missing_expected_cve_is_a_failure():
    assert compare_case(case(), summary())['checks'][0]['verdict'] == 'MISSING_FINDING'


def test_false_positive_on_fixed_component():
    assert compare_case(case('fixed'), summary(True))['checks'][0]['verdict'] == 'FALSE_POSITIVE'


def test_missing_or_wrong_version_component_cannot_pass_negative_check():
    assert compare_case(case('fixed'), {})['checks'][0]['verdict'] == 'UNRESOLVED_INVENTORY_EMPTY'
    assert compare_case(case('fixed'), summary(version='8.4.0'))['checks'][0]['verdict'] == 'UNRESOLVED_COMPONENT_MISSING'


def test_failed_run_cannot_pass_even_with_partial_finding():
    assert compare_case(case(), summary(True), False)['checks'][0]['verdict'] == 'UNRESOLVED_RUN_FAILED'


def test_cve_on_unrelated_component_is_not_a_match():
    observed = summary(True)
    observed['findings'][0]['component'] = 'some-other-library'
    assert compare_case(case(), observed)['checks'][0]['verdict'] == 'MISSING_FINDING'


def test_absent_excluded_plugin_passes_only_on_completed_scan():
    expected = case('excluded')
    expected['inventory'] = []
    assert compare_case(expected, summary())['checks'][0]['verdict'] == 'MATCH'
    assert compare_case(expected, {}, False)['checks'][0]['verdict'] == 'UNRESOLVED_RUN_FAILED'
