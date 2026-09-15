# Private-beta delivery ownership and zero-cost policy

This is the operating record for deployment card d01. Development and the
private beta remain pre-production and must cost exactly zero. A provider is
not approved merely because it has a free allowance: usage-billed services and
automatic upgrades are prohibited.

Founder decision (2026-09-15): personal ownership of `yahelil/PandaX` and
provider recovery access are accepted during development. Moving resources to
company-controlled ownership and verifying recovery are deferred until before
an external pilot or production release and do not block d01 completion.

## Locked provider policy

| Service | Allowed private-beta configuration | Prohibited configuration |
|---|---|---|
| GitHub | Private repository with individual accounts and least-privilege access; `yahelil/PandaX` is accepted during development | Shared credentials; paid add-ons; personal ownership after the external-pilot gate |
| Cloudflare | Pages/static assets, DNS, Email Routing, and one cron-only Worker on Free | R2; paid plans; usage-billed add-ons; automatic upgrades |
| Supabase | Two Free projects for staging and beta; PostgreSQL, Auth, and private Storage | Payment method; Pro; PITR; custom domains; automatic upgrades |
| Render | Two sleeping Free API services without persistent disks | Paid instances; persistent application data on the Render filesystem |
| Resend | Free account with internal stops at 80 messages/day and 2,000/month | Paid plan; unrestricted sending; automatic upgrade |
| PyPI | Company-controlled publishing identity; scoped project token only when a release exists | Shared password; account-wide token in CI; publishing from a personal-only identity |
| Signing | Customer private keys remain local; release keys use separate company-controlled custody | Customer private keys on the server; shared or repository-stored private keys |

No password, recovery code, private key, API token, or payment method belongs in
the repository, CI logs, screenshots, Trello, or support messages.

## Verification record — 2026-09-15

| Resource | Verified state | Remaining owner action |
|---|---|---|
| GitHub repository | `yahelil/PandaX` is private. The implementer has `WRITE`, not `ADMIN`. Personal ownership is founder-approved for development. | Before an external pilot, create a company organization, transfer the repository, and grant individual roles. |
| Cloudflare membership | The invited implementer membership is `Active`; the `pandax.online` zone and its subscription show `Free plan`. The account still has a personal-email display name. | Before an external pilot, rename the account for PandaX and establish company-controlled ownership/recovery. |
| Cloudflare billing | The visible zone is on Free and R2 is not enabled; the implementer cannot view account billing. | Before an external pilot, an account owner must verify that no paid subscription or automatic upgrade is active. |
| Cloudflare R2 | The dashboard shows the R2 subscription offer, so R2 is not enabled. | None; do not activate it. |
| Cloudflare Email Routing | Routing is enabled and existing aliases are active. `security@pandax.online` and `support@pandax.online` are not configured. | Add and verify both aliases before publishing them for external support. |
| `pandax.online` registrar | The zone is active on Cloudflare Free; registrar ownership and recovery were not available to the implementer. | Verify company ownership, renewal responsibility, and recovery before an external pilot. |
| Supabase | Not provisioned or authenticated in this environment. | Provision only when its implementation card needs it, using Free without a payment method; verify company ownership before an external pilot. |
| Render | Not provisioned or authenticated in this environment. | Provision only when its deployment card needs it, using Free; verify company ownership before an external pilot. |
| Resend | Not provisioned or authenticated in this environment. | Provision only when email delivery is implemented, using Free and documented hard stops; verify company ownership before an external pilot. |
| PyPI | The intended `actis` and `actis-evidence-verifier` project names return no published project. | Defer account recovery and scoped tokens until publishing is implemented; require company ownership before the first external release. |
| Release signing | No company release identity has been verified. | Establish company-controlled signing custody and recovery before signed packages are released. |

The remaining actions above are gates for the dependent deployment, external
pilot, or release—not blockers for d01 development completion. Record completed
checks and the verifier's identity in the d01 Trello card; do not paste secret
values.

## Capacity stops

Warn administrators at 70%, block optional/background growth at 80%, and reject
new growth at the hard stop. Never upgrade automatically.

| Resource | Hard stop |
|---|---:|
| Collector package | 25 MB |
| Other stored object | 50 MB |
| Active storage per application organization | 200 MB |
| Supabase Storage per Supabase organization | 800 MB |
| PostgreSQL per Supabase organization | 350 MB |
| Resend | 80/day and 2,000/month |

If staging and beta share a Supabase organization, reserve 200/600 MB of Storage
and 100/250 MB of PostgreSQL respectively. Do not borrow unused staging capacity.
Suspend staging first if the combined Render Free allowance is threatened.

## Access and deferred ownership rules

1. Personal ownership is accepted during development. Establish at least one
   company-controlled owner/recovery path before an external pilot or release.
2. Give people individual accounts; never share root credentials.
3. Use the narrowest project/deployment token that works and rotate it when a
   maintainer leaves or a secret may have been exposed.
4. Once recovery is established, keep recovery material separately from the
   backup computer.
5. Do not create a deployment secret until the consuming deployment exists.
6. If a required permission is unavailable, record the provider, attempted
   action, required role, remaining owner step, and a safe validation command.

## D01 development checklist

- [x] The approved zero-cost configurations and hard stops are documented.
- [x] The active Cloudflare zone is visibly on Free and R2 is not enabled.
- [x] Current GitHub access uses individual accounts; shared credentials are prohibited.
- [x] No secret, recovery material, private key, or payment detail is stored in the repository.
- [x] Company ownership and recovery checks are explicitly deferred to the external-pilot/release gate.
- [x] The evidence and founder decision are attached to the d01 Trello card without secrets.

Card d01 is Done when this checklist is verified, the implementing PR is merged,
and its evidence is attached to Trello. Before accepting external pilot data,
verify company ownership/recovery, billing state, required email aliases, and
provider quota enforcement on the cards that provision those resources.
