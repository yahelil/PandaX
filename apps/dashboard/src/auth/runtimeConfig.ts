export type RuntimeConfig =
  | { mode: "demo" }
  | {
      mode: "production";
      apiUrl: string;
      organizationId: string;
      oidc: {
        issuer: string;
        clientId: string;
        redirectUri: string;
        postLogoutRedirectUri: string;
        scope?: string;
        organizationClaim?: string;
        rolesClaim?: string;
      };
    };

type RuntimeEnvironment = Record<string, string | boolean | undefined>;

export function readRuntimeConfig(env: RuntimeEnvironment, origin = globalThis.location?.origin): RuntimeConfig {
  const mode = stringValue(env.VITE_ACTIS_MODE);
  if (mode === "demo") return { mode };
  if (mode !== "production") throw new Error("VITE_ACTIS_MODE must be explicitly set to demo or production.");
  const apiUrl = required(env, "VITE_ACTIS_API_URL");
  const organizationId = required(env, "VITE_ACTIS_ORGANIZATION_ID");
  const issuer = required(env, "VITE_ACTIS_OIDC_ISSUER");
  const clientId = required(env, "VITE_ACTIS_OIDC_CLIENT_ID");
  const redirectUri = stringValue(env.VITE_ACTIS_OIDC_REDIRECT_URI) || `${origin}/auth/callback`;
  const postLogoutRedirectUri = stringValue(env.VITE_ACTIS_OIDC_POST_LOGOUT_REDIRECT_URI) || `${origin}/`;
  return {
    mode,
    apiUrl,
    organizationId,
    oidc: {
      issuer,
      clientId,
      redirectUri,
      postLogoutRedirectUri,
      scope: stringValue(env.VITE_ACTIS_OIDC_SCOPE),
      organizationClaim: stringValue(env.VITE_ACTIS_OIDC_ORGANIZATION_CLAIM),
      rolesClaim: stringValue(env.VITE_ACTIS_OIDC_ROLES_CLAIM),
    },
  };
}

function required(env: RuntimeEnvironment, key: string): string {
  const value = stringValue(env[key]);
  if (!value) throw new Error(`${key} is required in production mode.`);
  return value;
}

function stringValue(value: string | boolean | undefined): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
