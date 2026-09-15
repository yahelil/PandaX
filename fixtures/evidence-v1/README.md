# Public-safe evidence v1 fixtures

These synthetic fixtures contain no customer data, secrets, or private keys.
Use `trusted-valid.pem` as the separately delivered trust anchor except for the
`wrong-key` case, which deliberately uses `trusted-wrong.pem`.

| Bundle | Trusted key | Expected status |
|---|---|---|
| `valid` | `trusted-valid.pem` | `trusted` |
| `tampered` | `trusted-valid.pem` | `invalid` |
| `missing` | `trusted-valid.pem` | `incomplete` |
| `extra` | `trusted-valid.pem` | `invalid` |
| `wrong-key` | `trusted-wrong.pem` | `untrusted` |

`valid` is immutable compatibility evidence. The other directories are copies
with exactly one deliberate fault: changed evidence bytes, a missing listed
file, an unlisted file, or a separately supplied key that did not sign the
bundle. See `docs/evidence-format-v1.md` for the normative contract.
