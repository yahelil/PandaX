# Private-beta delivery ownership and zero-cost policy

This is the operating record for deployment card d01. The private beta remains
pre-production and must cost exactly zero. A provider is not approved merely
because it has a free allowance: usage-billed services and automatic upgrades
are prohibited.

## Locked provider policy

| Service | Allowed private-beta configuration | Prohibited configuration |
|---|---|---|
| GitHub | Private repository in the company organization; individual accounts and least-privilege access | Personal repository as the long-term owner; shared credentials; paid add-ons |
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
| GitHub repository | `yahelil/PandaX` is private. The implementer has `WRITE`, not `ADMIN`. No `PandaXHQ` organization is accessible. | Create the free `PandaXHQ` organization, transfer the repository, and grant each team member an individual role. |
| Cloudflare membership | The invited implementer membership is `Active`; the `pandax.online` zone and its subscription show `Free plan`. The account still has a personal-email display name. | Rename the account for PandaX and keep a separate company-controlled owner/recovery path. |
| Cloudflare billing | The implementer cannot view account billing. | An account owner must verify that no payment method, paid subscription, or automatic upgrade is active. |
| Cloudflare R2 | The dashboard shows the R2 subscription offer, so R2 is not enabled. | None; do not activate it. |
| Cloudflare Email Routing | Routing is enabled and existing aliases are active. Required `security@pandax.online` and `support@pandax.online` aliases are absent. | Route both required aliases to the company team mailbox and verify delivery. |
| `pandax.online` registrar | The zone is active on Cloudflare Free; registrar ownership and recovery were not available to the implementer. | Verify company ownership, renewal responsibility, and recovery access at the registrar. |
| Supabase | Not provisioned or authenticated in this environment. | Create a company-controlled Free organization before d02; create staging and beta projects without a payment method. |
| Render | Not provisioned or authenticated in this environment. | Create a company-controlled Free account before d05. |
| Resend | Not provisioned or authenticated in this environment. | Create a company-controlled Free account and verify the company mail domain before d05. |
| PyPI | The intended `actis` and `actis-evidence-verifier` project names return no published project. | Establish company-controlled recovery before the first release; defer tokens until publishing is implemented. |
| Release signing | No company release identity has been verified. | Establish offline company-controlled recovery before signed packages are released. |

The owner actions above are deployment blockers, not reasons to stop independent
repository work. Record completed checks and the verifier's identity in the d01
Trello card; do not paste secret values.

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

## Access and recovery rules

1. Keep at least one company-controlled owner/recovery path for every provider.
2. Give people individual accounts; never share root credentials.
3. Use the narrowest project/deployment token that works and rotate it when a
   maintainer leaves or a secret may have been exposed.
4. Keep recovery material separately from the backup computer.
5. Do not create a deployment secret until the consuming deployment exists.
6. If a required permission is unavailable, record the provider, attempted
   action, required role, remaining owner step, and a safe validation command.

## Validation checklist

- [ ] Every row above has a company-controlled owner and recovery path.
- [ ] Every maintainer uses an individual account with only required access.
- [ ] No billing method, paid plan, paid add-on, PITR, R2, or automatic upgrade is active.
- [ ] Provider quota alerts and hard stops are configured before pilot data is accepted.
- [ ] Deployment credentials are scoped, stored outside the repository, and recoverable.
- [ ] The evidence comment is attached to the d01 Trello card without secrets.

Card d01 is Done only when every checkbox is verified, the implementing PR is
merged, and its evidence is attached to Trello.
