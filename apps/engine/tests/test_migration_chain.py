from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_production_migrations_form_one_ordered_head():
    root = Path(__file__).resolve().parents[3]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    scripts = ScriptDirectory.from_config(config)

    assert scripts.get_heads() == ["20260915_0010"]
    assert [revision.revision for revision in scripts.walk_revisions()] == [
        "20260915_0010",
        "20260914_0009",
        "20260914_0008",
        "20260914_0007",
        "20260914_0006",
        "20260914_0005",
        "20260914_0004",
        "20260914_0003",
        "20260914_0002",
        "20260914_0001",
    ]
