from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

VerificationStatus = Literal["trusted", "untrusted", "invalid", "incomplete"]


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    category: Literal["integrity", "bundle_signature", "signer_trust"]
    detail: str = ""


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    integrity_ok: bool
    signature_valid: bool
    signer_trust: Literal["trusted", "untrusted", "not_configured"]
    reason: str
    bundle_key_fingerprint: str | None = None
    trusted_key_fingerprint: str | None = None
    checks: list[Check] = field(default_factory=list)
    schema: str = "pandax/verification-result/v1"

    @property
    def ok(self) -> bool:
        return self.status == "trusted"

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["ok"] = self.ok
        return result

