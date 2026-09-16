import { type FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { usePermission } from "../auth";
import { useDemo } from "../data/DemoProvider";
import type { Integration, ManagedRole, OrganizationProfileUpdate, TeamMember } from "../data/types";
import { PageHeader, StatusPill, formatDate, titleCase } from "./PageKit";
import "./pages.css";

const sections = [
  { id: "organization", label: "Organization" },
  { id: "team", label: "Team & Access" },
  { id: "integrations", label: "Integrations" },
  { id: "notifications", label: "Notifications" },
  { id: "security", label: "Security & Retention" },
  { id: "appearance", label: "Appearance" },
] as const;

const managedRoles: Array<{ value: ManagedRole; label: string; description: string }> = [
  { value: "org_admin", label: "Org Admin", description: "Organization, access, integrations, and policy." },
  { value: "compliance_operator", label: "Compliance Operator", description: "Compliance workflows, evidence, and remediation." },
  { value: "security_reviewer", label: "Security Reviewer", description: "Finding decisions and product-security review." },
  { value: "authorized_approver", label: "Authorized Approver", description: "Controlled document approvals." },
  { value: "read_only_auditor", label: "Read-only Auditor", description: "Read-only workspace and audit access." },
];

type Section = typeof sections[number]["id"];
type Feedback = { tone: "success" | "error"; message: string };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Change could not be saved.";
}

function useMutationFeedback() {
  const [pending, setPending] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>();
  const run = async (operation: () => unknown | Promise<unknown>, success: string): Promise<boolean> => {
    setPending(true);
    setFeedback(undefined);
    try {
      await operation();
      setFeedback({ tone: "success", message: success });
      return true;
    } catch (error) {
      setFeedback({ tone: "error", message: errorMessage(error) });
      return false;
    } finally {
      setPending(false);
    }
  };
  return { pending, feedback, run };
}

function MutationFeedback({ feedback }: { feedback?: Feedback }) {
  if (!feedback) return null;
  const role = feedback.tone === "error" ? "alert" : "status";
  return <div className={`settings-feedback settings-feedback--${feedback.tone}`} role={role} aria-live="polite">{feedback.message}</div>;
}

export function SettingsPage() {
  const { section = "organization" } = useParams();
  const canManageSettings = usePermission("manage_settings");
  const current = (sections.some((item) => item.id === section) ? section : "organization") as Section;
  return <main className="page">
    <PageHeader eyebrow="Administration" title="Settings" description="Manage organization policy, access, integrations, and workspace preferences." />
    <div className="settings-layout">
      <nav className="panel settings-nav" aria-label="Settings sections">
        {sections.map((item) => <Link className={current === item.id ? "active" : ""} key={item.id} to={`/settings/${item.id}`}>{item.label}</Link>)}
      </nav>
      <div className="settings-content">
        {!canManageSettings ? <div className="notice">Settings are read-only. Org Admin permission is required to make changes.</div> : null}
        <fieldset className="settings-permission-boundary" disabled={!canManageSettings}>
          {current === "organization" ? <OrganizationSettings /> : null}
          {current === "team" ? <TeamSettings /> : null}
          {current === "integrations" ? <IntegrationSettings /> : null}
          {current === "notifications" ? <NotificationSettings /> : null}
          {current === "security" ? <SecuritySettings /> : null}
          {current === "appearance" ? <AppearanceSettings /> : null}
        </fieldset>
      </div>
    </div>
  </main>;
}

function OrganizationSettings() {
  const { state, actions } = useDemo();
  const organization = state.organization;
  const [form, setForm] = useState<Required<OrganizationProfileUpdate>>({ name: organization.name, legalName: organization.legalName, country: organization.country, registrationNumber: organization.registrationNumber, defaultTimezone: organization.defaultTimezone });
  const mutation = useMutationFeedback();
  useEffect(() => setForm({ name: organization.name, legalName: organization.legalName, country: organization.country, registrationNumber: organization.registrationNumber, defaultTimezone: organization.defaultTimezone }), [organization.name, organization.legalName, organization.country, organization.registrationNumber, organization.defaultTimezone]);
  const dirty = Object.entries(form).some(([key, value]) => value !== organization[key as keyof OrganizationProfileUpdate]);
  const change = (key: keyof typeof form, value: string) => setForm((current) => ({ ...current, [key]: value }));
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void mutation.run(() => actions.updateOrganization({ ...form, country: form.country.toUpperCase() }), "Organization profile saved and added to audit history.");
  };
  return <form className="panel setting-section" onSubmit={submit} aria-busy={mutation.pending}>
    <div><h2>Organization</h2><p className="muted">Legal identity and defaults used in CRA documentation.</p></div>
    <div className="form-grid">
      <div className="field"><label htmlFor="organization-display-name">Display name</label><input id="organization-display-name" className="input-field" value={form.name} required maxLength={200} onChange={(event) => change("name", event.target.value)} /></div>
      <div className="field"><label htmlFor="organization-legal-name">Legal name</label><input id="organization-legal-name" className="input-field" value={form.legalName} required maxLength={240} onChange={(event) => change("legalName", event.target.value)} /></div>
      <div className="field"><label htmlFor="organization-registration">Registration number</label><input id="organization-registration" className="input-field" value={form.registrationNumber} required maxLength={120} onChange={(event) => change("registrationNumber", event.target.value)} /></div>
      <div className="field"><label htmlFor="organization-country">Country code</label><input id="organization-country" className="input-field" value={form.country} required minLength={2} maxLength={2} pattern="[A-Za-z]{2}" autoCapitalize="characters" aria-describedby="organization-country-hint" onChange={(event) => change("country", event.target.value)} /><span className="field-hint" id="organization-country-hint">ISO two-letter code, such as DE.</span></div>
      <div className="field"><label htmlFor="organization-timezone">Default timezone</label><input id="organization-timezone" className="input-field" value={form.defaultTimezone} required maxLength={80} placeholder="Europe/Berlin" onChange={(event) => change("defaultTimezone", event.target.value)} /></div>
    </div>
    <MutationFeedback feedback={mutation.feedback} />
    <div className="settings-form-actions"><button className="button-primary" type="submit" disabled={!dirty || mutation.pending}>{mutation.pending ? "Saving…" : "Save organization"}</button></div>
  </form>;
}

function TeamSettings() {
  const { state } = useDemo();
  const [editingId, setEditingId] = useState<string>();
  const member = state.members.find((item) => item.id === editingId);
  return <section className="panel">
    <div className="section-header"><div><h2>Team & Access</h2><p>Fixed roles separate operational work, approval, administration, and audit access.</p></div><button className="button-primary" type="button" disabled aria-describedby="team-invite-unavailable">Invite member</button></div>
    <div className="settings-inline-note" id="team-invite-unavailable">Invitations are provisioned by your identity provider. Role and access changes are available here.</div>
    <div className="data-table-wrap settings-table-wrap"><table className="data-table settings-table"><thead><tr><th>Member</th><th>Title</th><th>Roles</th><th>Status</th><th>Last active</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{state.members.map((item) => <tr key={item.id}><td><div className="cell-primary"><span className="cell-strong">{item.name}</span><small>{item.email}</small></div></td><td>{item.title}</td><td>{item.roles.map(titleCase).join(" · ")}</td><td><StatusPill value={item.status} /></td><td>{item.lastActiveAt ? formatDate(item.lastActiveAt, true) : "Invitation pending"}</td><td><button className="button-small" type="button" aria-expanded={editingId === item.id} onClick={() => setEditingId((current) => current === item.id ? undefined : item.id)}>{editingId === item.id ? "Close" : "Manage"}</button></td></tr>)}</tbody></table></div>
    {member ? <TeamMemberEditor key={member.id} member={member} onClose={() => setEditingId(undefined)} /> : null}
  </section>;
}

function TeamMemberEditor({ member, onClose }: { member: TeamMember; onClose: () => void }) {
  const { actions, state } = useDemo();
  const [title, setTitle] = useState(member.title);
  const [roles, setRoles] = useState<ManagedRole[]>(member.roles);
  const mutation = useMutationFeedback();
  const toggleRole = (role: ManagedRole) => setRoles((current) => current.includes(role) ? current.filter((item) => item !== role) : [...current, role]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!roles.length) return;
    void mutation.run(() => actions.updateTeamMember(member.id, { title: title.trim(), roles }), `${member.name}'s access was updated.`);
  };
  return <form className="settings-editor" onSubmit={submit} aria-busy={mutation.pending}>
    <div className="section-header"><div><h3>Manage {member.name}</h3><p>Role changes take effect after member’s next sign-in.</p></div><button type="button" onClick={onClose}>Cancel</button></div>
    <div className="settings-editor-body">
      <div className="field"><label htmlFor={`member-title-${member.id}`}>Title</label><input id={`member-title-${member.id}`} className="input-field" value={title} required maxLength={160} onChange={(event) => setTitle(event.target.value)} /></div>
      <fieldset className="field"><legend>Roles</legend><div className="settings-role-grid">{managedRoles.map((role) => <label key={role.value} className="settings-check-card"><input type="checkbox" checked={roles.includes(role.value)} onChange={() => toggleRole(role.value)} /><span><strong>{role.label}</strong><small>{role.description}</small></span></label>)}</div><span className={`field-hint ${roles.length ? "" : "danger-text"}`}>{roles.length ? "One or more roles may be assigned." : "Select at least one role."}</span></fieldset>
      {member.id === state.currentUserId ? <div className="notice notice-warning">You are editing your own directory record. Current session permissions remain unchanged until you sign in again.</div> : null}
      <MutationFeedback feedback={mutation.feedback} />
      <div className="settings-form-actions"><button className="button-primary" type="submit" disabled={mutation.pending || !title.trim() || !roles.length}>{mutation.pending ? "Saving…" : "Save access"}</button></div>
    </div>
  </form>;
}

function IntegrationSettings() {
  const { state } = useDemo();
  const [editingId, setEditingId] = useState<string>();
  const integration = state.integrations.find((item) => item.id === editingId);
  return <section className="panel">
    <div className="section-header"><div><h2>Integrations</h2><p>Connect evidence collection and action notifications using externally managed credentials.</p></div></div>
    {state.integrations.map((item) => <div className="setting-row settings-integration-row" key={item.id}><div><strong>{item.name}</strong><p>{item.description}{item.lastSyncAt ? ` Last activity ${formatDate(item.lastSyncAt, true)}.` : ""}</p><small className="muted">{item.secretReference ? "Credentials configured" : "Credentials not configured"}</small></div><div className="inline-actions"><StatusPill value={item.status} /><button type="button" aria-expanded={editingId === item.id} onClick={() => setEditingId((current) => current === item.id ? undefined : item.id)}>{editingId === item.id ? "Close" : item.status === "not_connected" ? "Connect" : "Configure"}</button></div></div>)}
    {integration ? <IntegrationEditor key={integration.id} integration={integration} onClose={() => setEditingId(undefined)} /> : null}
  </section>;
}

function integrationFields(integration: Integration): Array<{ key: string; label: string; placeholder: string }> {
  if (integration.type === "email") return [{ key: "from_address", label: "From address", placeholder: "compliance@example.com" }];
  if (integration.type === "collector") return [{ key: "collector_id", label: "Collector ID", placeholder: "production-eu-1" }];
  if (integration.type === "webhook") return [{ key: "endpoint_name", label: "Endpoint name", placeholder: "security-operations" }];
  return [{ key: "site", label: "Site", placeholder: "company.atlassian.net" }, { key: "project_key", label: "Project key", placeholder: "SEC" }];
}

function IntegrationEditor({ integration, onClose }: { integration: Integration; onClose: () => void }) {
  const { actions } = useDemo();
  const [configuration, setConfiguration] = useState<Record<string, unknown>>(integration.configuration);
  const [secretReference, setSecretReference] = useState(integration.secretReference ?? "");
  const mutation = useMutationFeedback();
  const fields = integrationFields(integration);
  const save = (event: FormEvent) => {
    event.preventDefault();
    void mutation.run(() => actions.updateIntegration(integration.id, { configuration, secretReference: secretReference.trim() || null, status: "connected" }), `${integration.name} is connected and configured.`);
  };
  const disconnect = () => {
    if (!window.confirm(`Disconnect ${integration.name}? Stored configuration will remain, but delivery and collection will stop.`)) return;
    void mutation.run(() => actions.updateIntegration(integration.id, { status: "not_connected", secretReference: null }), `${integration.name} was disconnected.`);
  };
  return <form className="settings-editor" onSubmit={save} aria-busy={mutation.pending}>
    <div className="section-header"><div><h3>{integration.status === "not_connected" ? "Connect" : "Configure"} {integration.name}</h3><p>Credentials stay in your external secret manager; Actis stores only the reference.</p></div><button type="button" onClick={onClose}>Cancel</button></div>
    <div className="settings-editor-body">
      <div className="form-grid">{fields.map((field) => <div className="field" key={field.key}><label htmlFor={`integration-${integration.id}-${field.key}`}>{field.label}</label><input id={`integration-${integration.id}-${field.key}`} className="input-field" value={String(configuration[field.key] ?? "")} required maxLength={320} placeholder={field.placeholder} onChange={(event) => setConfiguration((current) => ({ ...current, [field.key]: event.target.value }))} /></div>)}
        {integration.type === "email" ? <div className="field"><label htmlFor={`integration-provider-${integration.id}`}>Provider</label><select id={`integration-provider-${integration.id}`} className="select-field" value={String(configuration.provider ?? "smtp")} onChange={(event) => setConfiguration((current) => ({ ...current, provider: event.target.value }))}><option value="smtp">SMTP</option><option value="sendgrid">SendGrid</option><option value="ses">Amazon SES</option><option value="microsoft_graph">Microsoft Graph</option></select></div> : null}
        {integration.type === "collector" ? <div className="field"><label htmlFor={`integration-environment-${integration.id}`}>Environment</label><select id={`integration-environment-${integration.id}`} className="select-field" value={String(configuration.environment ?? "production")} onChange={(event) => setConfiguration((current) => ({ ...current, environment: event.target.value }))}><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option></select></div> : null}
        <div className="field span-2"><label htmlFor={`integration-secret-${integration.id}`}>External secret reference</label><input id={`integration-secret-${integration.id}`} className="input-field mono" value={secretReference} required pattern="(vault|aws-secrets|gcp-secret|azure-keyvault)://[A-Za-z0-9._/@-]+" placeholder="vault://organization/integration" aria-describedby={`integration-secret-hint-${integration.id}`} onChange={(event) => setSecretReference(event.target.value)} /><span id={`integration-secret-hint-${integration.id}`} className="field-hint">Accepted schemes: vault, aws-secrets, gcp-secret, or azure-keyvault.</span></div>
      </div>
      <MutationFeedback feedback={mutation.feedback} />
      <div className="settings-form-actions">{integration.status !== "not_connected" ? <button className="button-danger" type="button" disabled={mutation.pending} onClick={disconnect}>Disconnect</button> : null}<button className="button-primary" type="submit" disabled={mutation.pending}>{mutation.pending ? "Saving…" : integration.status === "not_connected" ? "Connect integration" : "Save configuration"}</button></div>
    </div>
  </form>;
}

function NotificationSettings() {
  const { state, actions } = useDemo();
  const settings = state.settings.notifications;
  const mutation = useMutationFeedback();
  const toggles = [{ key: "urgentFindings", label: "Urgent findings", body: "Confirmed, reachable, or actively exploited vulnerabilities." }, { key: "deadlineWarnings", label: "Deadline warnings", body: "CRA obligations approaching their action window." }, { key: "monitoringFailures", label: "Monitoring failures", body: "Advisory sources or scheduled checks needing attention." }, { key: "approvalRequests", label: "Approval requests", body: "Documents and reports ready for authorized approval." }] as const;
  return <section className="panel setting-section" aria-busy={mutation.pending}><div><h2>Notifications</h2><p className="muted">Action-required alerts only. Routine changes remain in Recent Changes.</p></div>{toggles.map((item) => <div className="setting-row" key={item.key}><div><strong>{item.label}</strong><p>{item.body}</p></div><button className="switch" type="button" role="switch" aria-checked={settings[item.key]} aria-label={item.label} disabled={mutation.pending} onClick={() => void mutation.run(() => actions.updateSettings("notifications", { [item.key]: !settings[item.key] }), `${item.label} preference saved.`)} /></div>)}<div className="field"><label htmlFor="email-digest">Email digest</label><select id="email-digest" className="select-field" value={settings.emailDigest} disabled={mutation.pending} onChange={(event) => void mutation.run(() => actions.updateSettings("notifications", { emailDigest: event.target.value as typeof settings.emailDigest }), "Email digest preference saved.")}><option value="off">Off</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></div><MutationFeedback feedback={mutation.feedback} /></section>;
}

function SecuritySettings() {
  const { state, actions } = useDemo();
  const settings = state.settings.security;
  const mutation = useMutationFeedback();
  const update = (patch: Partial<typeof settings>, success: string) => void mutation.run(() => actions.updateSettings("security", patch), success);
  return <section className="panel setting-section" aria-busy={mutation.pending}><div><h2>Security & Retention</h2><p className="muted">Organization-wide evidence handling and session policy.</p></div><div className="setting-row"><div><strong>Require multi-factor authentication</strong><p>Enforced for members when production identity is connected.</p></div><button className="switch" type="button" role="switch" aria-label="Require multi-factor authentication" aria-checked={settings.requireMfa} disabled={mutation.pending} onClick={() => update({ requireMfa: !settings.requireMfa }, "Multi-factor authentication policy saved.")} /></div><div className="setting-row"><div><strong>Allow raw product artifacts</strong><p>Each upload still requires an explicit privacy acknowledgement.</p></div><button className="switch" type="button" role="switch" aria-label="Allow raw product artifacts" aria-checked={settings.allowRawArtifacts} disabled={mutation.pending} onClick={() => update({ allowRawArtifacts: !settings.allowRawArtifacts }, "Raw artifact policy saved.")} /></div><div className="form-grid"><div className="field"><label htmlFor="session-timeout">Session timeout</label><select id="session-timeout" className="select-field" value={settings.sessionTimeoutMinutes} disabled={mutation.pending} onChange={(event) => update({ sessionTimeoutMinutes: Number(event.target.value) }, "Session timeout saved.")}><option value="30">30 minutes</option><option value="60">1 hour</option><option value="240">4 hours</option><option value="480">8 hours</option></select></div><div className="field"><label htmlFor="evidence-retention">Evidence retention</label><select id="evidence-retention" className="select-field" value={settings.evidenceRetentionMonths} disabled={mutation.pending} onChange={(event) => update({ evidenceRetentionMonths: Number(event.target.value) }, "Evidence retention policy saved.")}><option value="24">24 months</option><option value="60">5 years</option><option value="120">10 years</option></select></div></div><MutationFeedback feedback={mutation.feedback} /></section>;
}

function AppearanceSettings() {
  const { state, actions, adapterStatus } = useDemo();
  const settings = state.settings.appearance;
  const mutation = useMutationFeedback();
  const update = (patch: Partial<typeof settings>, success: string) => void mutation.run(() => actions.updateSettings("appearance", patch), success);
  return <section className="panel setting-section" aria-busy={mutation.pending}><div><h2>Appearance</h2><p className="muted">Theme and information density follow you across the workspace.</p></div><fieldset className="field" disabled={mutation.pending}><legend>Theme</legend><div className="choice-grid">{(["light", "dark", "system"] as const).map((theme) => <label className="choice-card" key={theme}><input type="radio" name="theme" checked={settings.theme === theme} onChange={() => update({ theme }, `${titleCase(theme)} theme saved.`)} /><strong>{titleCase(theme)}</strong><span>{theme === "system" ? "Match the operating system preference." : `${titleCase(theme)} workspace surfaces and charts.`}</span></label>)}</div></fieldset><div className="field"><label htmlFor="appearance-density">Density</label><select id="appearance-density" className="select-field" value={settings.density} disabled={mutation.pending} onChange={(event) => update({ density: event.target.value as typeof settings.density }, "Workspace density saved.")}><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></div><MutationFeedback feedback={mutation.feedback} />{adapterStatus.mode === "fixture" ? <div className="notice"><strong>Demo data</strong><br />Reset returns decisions, assignments, approvals, analyses, filters, and settings to presentation baseline. <button className="button-small settings-reset" type="button" onClick={actions.reset}>Reset demo</button></div> : null}</section>;
}
