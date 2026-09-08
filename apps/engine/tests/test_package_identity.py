import hashlib
import json
from types import SimpleNamespace

from pandax.stages import sbom


def test_syft_stage_resolves_exact_binary_identity_and_keeps_original(ctx, monkeypatch):
    from pandax import package_identity

    ctx.extracted_dir = ctx.path('extracted')
    ctx.extracted_dir.mkdir()
    jar = ctx.extracted_dir / 'renamed.jar'
    jar.write_bytes(b'publisher artifact')
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    coordinate = 'pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.98'
    monkeypatch.setattr(package_identity, 'IDENTITIES', {digest: dict(
        name='tomcat-catalina', version='9.0.98', purl=coordinate,
        url='https://repo.maven.apache.org/maven2/example.jar')})
    original = dict(specVersion='1.6', components=[dict(
        name='catalina', version='9.0.98', purl='pkg:maven/org.apache.tomcat-catalina/catalina@9.0.98',
        **{'bom-ref': 'original-ref'}, properties=[
            dict(name='syft:location:0:path', value='/renamed.jar')])])
    monkeypatch.setattr(sbom, 'syft_binary', lambda: jar)
    monkeypatch.setattr(sbom, 'syft_version', lambda _: 'test')
    def scan(*args, **kwargs):
        ctx.path('sbom.cdx.json').write_text(json.dumps(original))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(sbom.subprocess, 'run', scan)
    ctx.path('ingest_tree.json').write_text('{}')
    list(sbom.run(ctx))
    assert ctx.components[0]['purl'] == coordinate
    assert ctx.components[0]['bom_ref'] == 'original-ref'
    assert json.loads(ctx.path('sbom.syft.json').read_text()) == original
    assert any(p['name'] == 'pandax:identity-sha256' and p['value'] == digest
               for p in ctx.sbom['components'][0]['properties'])
    assert any(r['path'] == 'sbom.syft.json' for r in ctx.ledger.records[-1]['outputs'])


def test_unrecognised_binary_and_traversal_keep_syft_identity(tmp_path, monkeypatch):
    from pandax import package_identity

    known = b'publisher artifact'
    monkeypatch.setattr(package_identity, 'IDENTITIES', {
        hashlib.sha256(known).hexdigest(): dict(name='tomcat-catalina', version='9.0.99',
            purl='pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.99', url='https://example.test/jar')})
    root = tmp_path / 'scan'
    root.mkdir()
    jar = tmp_path / 'catalina.jar'
    jar.write_bytes(known)
    (root / 'catalina.jar').write_bytes(b'different bytes')
    for location in ('catalina.jar', '../catalina.jar', 'C:/outside/catalina.jar'):
        component = dict(name='catalina', version='9.0.99', purl='pkg:maven/unknown/catalina@9.0.99',
                         properties=[dict(name='syft:location:0:path', value=location)])
        original = json.loads(json.dumps(component))
        package_identity.enrich({'components': [component]}, root)
        assert component == original
