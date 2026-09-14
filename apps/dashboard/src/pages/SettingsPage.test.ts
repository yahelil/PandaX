import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

import { createDemoState, DEMO_IDS } from "../data/fixtures";
import { FixtureAdapter } from "../data/fixtureAdapter";
import { createGovernanceApi } from "../data/governanceApi";
import type { GovernanceApi, GovernanceIntegrationDto, GovernanceSettingsDto, GovernanceTeamMemberDto } from "../data/governanceApi";
import type { PortfolioApi } from "../data/portfolioApi";
import { ProductionAdapter } from "../data/productionAdapter";

const source = readFileSync(new URL("./SettingsPage.tsx", import.meta.url), "utf8");

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

describe("Settings mutations", () => {
  it("updates organization, team roles, integrations, and policy in fixture mode", async () => {
    const adapter = new FixtureAdapter(createDemoState(), false);
    await adapter.updateOrganization({ legalName: "Acme Connected Devices GmbH", country: "DE" });
    await adapter.updateTeamMember(DEMO_IDS.marcus, { title: "Principal Product Security Engineer", roles: ["compliance_operator"] });
    await adapter.updateIntegration("integration-jira", { status: "connected", secretReference: "vault://actis/acme/jira" });
    await adapter.updateSettings("security", { evidenceRetentionMonths: 60 });

    const state = adapter.getSnapshot();
    expect(state.organization).toMatchObject({ legalName: "Acme Connected Devices GmbH", country: "DE" });
    expect(state.members.find((item) => item.id === DEMO_IDS.marcus)).toMatchObject({ title: "Principal Product Security Engineer", roles: ["compliance_operator"], version: 2 });
    expect(state.integrations.find((item) => item.id === "integration-jira")).toMatchObject({ status: "connected", secretReference: "vault://actis/acme/jira", version: 2 });
    expect(state.settings.security.evidenceRetentionMonths).toBe(60);
  });

  it("serializes optimistic organization, role, and integration changes", async () => {
    const settings = {
      organization_id: "org/acme", version: 5,
      organization_profile: { name: "Acme", legal_name: "Acme GmbH", country: "DE", registration_number: "HRB-1", timezone: "Europe/Berlin" },
      notifications: { urgent_findings: true, deadline_warnings: true, monitoring_failures: true, approval_requests: true, email_digest: "daily" },
      security: { session_timeout_minutes: 60, evidence_retention_months: 120, require_mfa: true, allow_raw_artifacts: false },
      appearance: { theme: "system", density: "comfortable" }, analytics: { enabled: true, retention_days: 90 }, updated_by: "admin", updated_at: "2026-09-14T10:00:00Z",
    };
    const member = { id: "member-1", organization_id: "org/acme", subject: "oidc|one", name: "Alex Morgan", email: "alex@example.test", title: "Reviewer", initials: "AM", roles: ["security_reviewer"], status: "active", last_active_at: null, version: 3, created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-14T00:00:00Z" };
    const integration = { id: "jira-1", organization_id: "org/acme", name: "Jira Cloud", type: "jira", status: "connected", description: "Remediation work items", configuration: { site: "acme.atlassian.net", project_key: "SEC" }, secret_reference: "vault://actis/acme/jira", last_sync_at: null, version: 2, created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-14T00:00:00Z" };
    const responses = [json(settings), json(member), json(integration)];
    const fetcher = vi.fn<typeof fetch>(async () => responses.shift()!);
    const api = createGovernanceApi({ baseUrl: "/engine", fetch: fetcher });

    await api.updateSettings("org/acme", { expectedVersion: 4, organizationProfile: { legalName: "Acme GmbH", timezone: "Europe/Berlin" } });
    await api.updateTeamMember("org/acme", "member-1", { expectedVersion: 2, roles: ["security_reviewer"] });
    await api.updateIntegration("org/acme", "jira-1", { expectedVersion: 1, status: "connected", secretReference: "vault://actis/acme/jira" });

    expect(fetcher.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      ["/engine/v1/organizations/org%2Facme/settings", "PATCH"],
      ["/engine/v1/organizations/org%2Facme/team/member-1", "PATCH"],
      ["/engine/v1/organizations/org%2Facme/integrations/jira-1", "PATCH"],
    ]);
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({ expected_version: 4, organization_profile: { legal_name: "Acme GmbH", timezone: "Europe/Berlin" } });
    expect(JSON.parse(String(fetcher.mock.calls[1][1]?.body))).toEqual({ expected_version: 2, roles: ["security_reviewer"] });
    expect(JSON.parse(String(fetcher.mock.calls[2][1]?.body))).toEqual({ expected_version: 1, status: "connected", secret_reference: "vault://actis/acme/jira" });
  });

  it("updates production snapshots with server versions instead of fixture-only state", async () => {
    const initial = createDemoState();
    const settings: GovernanceSettingsDto = {
      organizationId: initial.organization.id, version: 1,
      organizationProfile: { name: initial.organization.name, legalName: initial.organization.legalName, country: initial.organization.country, registrationNumber: initial.organization.registrationNumber, timezone: initial.organization.defaultTimezone },
      notifications: initial.settings.notifications, security: initial.settings.security, appearance: initial.settings.appearance,
      analytics: initial.settings.analytics, updatedBy: initial.currentUserId, updatedAt: "2026-09-14T10:00:00Z",
    };
    const member: GovernanceTeamMemberDto = { id: DEMO_IDS.marcus, organizationId: initial.organization.id, subject: "oidc|marcus", name: "Marcus Chen", email: "marcus@example.test", title: "Product Security Engineer", initials: "MC", roles: ["compliance_operator"], status: "active", version: 1, createdAt: "2026-09-01T00:00:00Z", updatedAt: "2026-09-14T00:00:00Z" };
    const integration: GovernanceIntegrationDto = { id: "integration-jira", organizationId: initial.organization.id, name: "Jira Cloud", type: "jira", status: "not_connected", description: "Remediation work items", configuration: { site: "acme.atlassian.net", project_key: "SEC" }, version: 1, createdAt: "2026-09-01T00:00:00Z", updatedAt: "2026-09-14T00:00:00Z" };
    const updateSettings = vi.fn(async () => ({ ...settings, version: 2, organizationProfile: { ...settings.organizationProfile, legalName: "Acme Connected Devices GmbH" } }));
    const updateTeamMember = vi.fn(async () => ({ ...member, version: 2, roles: ["compliance_operator"] as const }));
    const updateIntegration = vi.fn(async () => ({ ...integration, version: 2, status: "connected" as const, secretReference: "vault://actis/acme/jira" }));
    const governance = {
      listCompliance: vi.fn(async () => []), listDocuments: vi.fn(async () => []), getSettings: vi.fn(async () => settings),
      listTeam: vi.fn(async () => [member]), listIntegrations: vi.fn(async () => [integration]),
      updateSettings, updateTeamMember, updateIntegration,
    } as unknown as GovernanceApi;
    const portfolio = {
      getOrganization: vi.fn(async () => initial.organization), listProducts: vi.fn(async () => []), listReleases: vi.fn(async () => []),
    } as unknown as PortfolioApi;
    const adapter = new ProductionAdapter({ organizationId: initial.organization.id, portfolioApi: portfolio, governanceApi: governance, fixtureAdapter: new FixtureAdapter(initial, false) });

    await adapter.initialize();
    await adapter.updateOrganization({ legalName: "Acme Connected Devices GmbH" });
    await adapter.updateTeamMember(DEMO_IDS.marcus, { roles: ["compliance_operator"] });
    await adapter.updateIntegration("integration-jira", { status: "connected", secretReference: "vault://actis/acme/jira" });

    expect(updateSettings).toHaveBeenCalledWith(initial.organization.id, { expectedVersion: 1, organizationProfile: { legalName: "Acme Connected Devices GmbH", timezone: undefined } });
    expect(updateTeamMember).toHaveBeenCalledWith(initial.organization.id, DEMO_IDS.marcus, { expectedVersion: 1, roles: ["compliance_operator"] });
    expect(updateIntegration).toHaveBeenCalledWith(initial.organization.id, "integration-jira", { expectedVersion: 1, status: "connected", secretReference: "vault://actis/acme/jira" });
    expect(adapter.getSnapshot()).toMatchObject({ organization: { legalName: "Acme Connected Devices GmbH" }, members: [{ roles: ["compliance_operator"], version: 2 }], integrations: [{ status: "connected", version: 2 }] });
  });

  it("exposes real actions, permission boundaries, disabled provisioning, and feedback", () => {
    for (const action of ["actions.updateOrganization", "actions.updateTeamMember", "actions.updateIntegration", "actions.updateSettings"]) expect(source).toContain(action);
    expect(source).toContain('disabled aria-describedby="team-invite-unavailable"');
    expect(source).toContain("Invitations are provisioned by your identity provider");
    expect(source).toContain('role={role} aria-live="polite"');
    expect(source).toContain("Org Admin permission is required");
  });
});
