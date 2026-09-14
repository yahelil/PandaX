import { describe, expect, it, vi } from "vitest";
import { BrowserOidcClient, type AuthSession } from "./oidcClient";
import { hasPermission } from "./permissions";
import { readRuntimeConfig } from "./runtimeConfig";

class MemoryStorage implements Storage {
  private values = new Map<string, string>();
  get length() { return this.values.size; }
  clear() { this.values.clear(); }
  getItem(key: string) { return this.values.get(key) ?? null; }
  key(index: number) { return [...this.values.keys()][index] ?? null; }
  removeItem(key: string) { this.values.delete(key); }
  setItem(key: string, value: string) { this.values.set(key, value); }
}

const jwt = (claims: Record<string, unknown>) => [
  { alg: "RS256", typ: "JWT" }, claims, "signature",
].map((part, index) => index === 2 ? part : btoa(JSON.stringify(part)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")).join(".");

describe("runtime authentication", () => {
  it("requires an explicit runtime mode and fails closed in production", () => {
    expect(readRuntimeConfig({ VITE_ACTIS_MODE: "demo" }, "https://actis.example")).toEqual({ mode: "demo" });
    expect(() => readRuntimeConfig({}, "https://actis.example")).toThrow(/explicitly set/);
    expect(() => readRuntimeConfig({ VITE_ACTIS_MODE: "production" }, "https://actis.example")).toThrow(/VITE_ACTIS_API_URL/);
    expect(readRuntimeConfig({
      VITE_ACTIS_MODE: "production",
      VITE_ACTIS_API_URL: "https://api.actis.example",
      VITE_ACTIS_ORGANIZATION_ID: "org-acme",
      VITE_ACTIS_OIDC_ISSUER: "https://identity.example",
      VITE_ACTIS_OIDC_CLIENT_ID: "actis-dashboard",
    }, "https://actis.example")).toMatchObject({
      mode: "production",
      oidc: { redirectUri: "https://actis.example/auth/callback" },
    });
  });

  it("maps roles to the same permissions enforced by the API", () => {
    expect(hasPermission(["compliance_operator"], "manage_portfolio")).toBe(true);
    expect(hasPermission(["compliance_operator"], "run_analysis")).toBe(true);
    expect(hasPermission(["compliance_operator"], "decide_findings")).toBe(true);
    expect(hasPermission(["authorized_approver"], "approve_documents")).toBe(true);
    expect(hasPermission(["read_only_auditor"], "manage_settings")).toBe(false);
    expect(hasPermission(["org_admin"], "approve_documents")).toBe(false);
  });

  it("restores an expired session through refresh-token rotation", async () => {
    const storage = new MemoryStorage();
    const previous: AuthSession = {
      accessToken: "expired",
      refreshToken: "refresh-one",
      expiresAt: 900_000,
      user: { subject: "user-1", organizationId: "org-acme", name: "Jane Doe", initials: "JD", roles: ["org_admin"] },
    };
    storage.setItem("actis.oidc.session.actis-dashboard", JSON.stringify(previous));
    const fetcher = vi.fn<typeof fetch>(async (input) => {
      if (String(input).includes("openid-configuration")) return new Response(JSON.stringify({
        issuer: "https://identity.example",
        authorization_endpoint: "https://identity.example/authorize",
        token_endpoint: "https://identity.example/token",
      }), { status: 200 });
      return new Response(JSON.stringify({
        access_token: jwt({ sub: "user-1", org_id: "org-acme", name: "Jane Doe", roles: ["org_admin"], exp: 9_999_999 }),
        refresh_token: "refresh-two",
        token_type: "Bearer",
        expires_in: 300,
      }), { status: 200 });
    });
    const client = new BrowserOidcClient({
      issuer: "https://identity.example",
      clientId: "actis-dashboard",
      organizationId: "org-acme",
      redirectUri: "https://actis.example/auth/callback",
      postLogoutRedirectUri: "https://actis.example/",
      fetch: fetcher,
      storage,
      location: { href: "https://actis.example/products", assign: vi.fn() },
      history: { replaceState: vi.fn() },
      now: () => 1_000_000,
    });

    const session = await client.initialize();

    expect(session).toMatchObject({ refreshToken: "refresh-two", expiresAt: 1_300_000, user: { organizationId: "org-acme", roles: ["org_admin"] } });
    const tokenRequest = fetcher.mock.calls.find(([input]) => String(input).endsWith("/token"));
    expect(String(tokenRequest?.[1]?.body)).toContain("grant_type=refresh_token");
    expect(String(tokenRequest?.[1]?.body)).toContain("refresh_token=refresh-one");
  });

  it("clears an expired session when no refresh credential exists", async () => {
    const storage = new MemoryStorage();
    storage.setItem("actis.oidc.session.actis-dashboard", JSON.stringify({
      accessToken: "expired", expiresAt: 1, user: { subject: "user-1", organizationId: "org-acme", name: "Jane", initials: "J", roles: ["read_only_auditor"] },
    }));
    const client = new BrowserOidcClient({
      issuer: "https://identity.example", clientId: "actis-dashboard", organizationId: "org-acme",
      redirectUri: "https://actis.example/auth/callback", postLogoutRedirectUri: "https://actis.example/",
      fetch: vi.fn(), storage, location: { href: "https://actis.example/", assign: vi.fn() }, history: { replaceState: vi.fn() }, now: () => 1_000,
    });
    expect(await client.initialize()).toBeNull();
    expect(storage.getItem("actis.oidc.session.actis-dashboard")).toBeNull();
  });
});
