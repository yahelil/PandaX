export type AuthRole =
  | "org_admin"
  | "compliance_operator"
  | "security_reviewer"
  | "authorized_approver"
  | "read_only_auditor";

export interface AuthUser {
  subject: string;
  organizationId: string;
  name: string;
  email?: string;
  initials: string;
  roles: AuthRole[];
}

export interface AuthSession {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number;
  user: AuthUser;
}

export interface OidcClientConfig {
  issuer: string;
  clientId: string;
  organizationId: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  scope?: string;
  organizationClaim?: string;
  rolesClaim?: string;
  fetch?: typeof globalThis.fetch;
  storage?: Storage;
  location?: Pick<Location, "href" | "assign">;
  history?: Pick<History, "replaceState">;
  crypto?: Crypto;
  now?: () => number;
}

export interface AuthClient {
  initialize(): Promise<AuthSession | null>;
  login(returnTo?: string): Promise<void>;
  logout(): Promise<void>;
  getAccessToken(): Promise<string | undefined>;
  getSession(): AuthSession | null;
  subscribe(listener: (session: AuthSession | null) => void): () => void;
}

interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
}

interface PendingAuthorization {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
}

interface TokenResponse {
  access_token: string;
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  token_type?: string;
}

const ROLE_ALIASES: Record<string, AuthRole> = {
  org_admin: "org_admin",
  compliance_operator: "compliance_operator",
  authorized_approver: "authorized_approver",
  security_reviewer: "security_reviewer",
  viewer: "read_only_auditor",
  read_only_auditor: "read_only_auditor",
};

export class BrowserOidcClient implements AuthClient {
  private readonly fetcher: typeof globalThis.fetch;
  private readonly storage: Storage;
  private readonly browserLocation: Pick<Location, "href" | "assign">;
  private readonly browserHistory: Pick<History, "replaceState">;
  private readonly cryptoApi: Crypto;
  private readonly now: () => number;
  private readonly sessionKey: string;
  private readonly pendingKey: string;
  private readonly listeners = new Set<(session: AuthSession | null) => void>();
  private session: AuthSession | null = null;
  private discovery?: OidcDiscovery;
  private initializePromise?: Promise<AuthSession | null>;
  private refreshPromise?: Promise<AuthSession | null>;

  constructor(private readonly config: OidcClientConfig) {
    this.fetcher = config.fetch ?? globalThis.fetch.bind(globalThis);
    this.storage = config.storage ?? globalThis.sessionStorage;
    this.browserLocation = config.location ?? globalThis.location;
    this.browserHistory = config.history ?? globalThis.history;
    this.cryptoApi = config.crypto ?? globalThis.crypto;
    this.now = config.now ?? Date.now;
    this.sessionKey = `actis.oidc.session.${config.clientId}`;
    this.pendingKey = `actis.oidc.pending.${config.clientId}`;
  }

  subscribe(listener: (session: AuthSession | null) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  getSession(): AuthSession | null {
    return this.session;
  }

  initialize(): Promise<AuthSession | null> {
    if (!this.initializePromise) this.initializePromise = this.restoreOrComplete();
    return this.initializePromise;
  }

  private async restoreOrComplete(): Promise<AuthSession | null> {
    const url = new URL(this.browserLocation.href);
    if (url.searchParams.has("code") || url.searchParams.has("error")) {
      return this.completeAuthorization(url);
    }
    this.session = this.readSession();
    if (!this.session) return null;
    if (this.session.expiresAt <= this.now() + 30_000) return this.refresh();
    return this.session;
  }

  async login(returnTo = currentPath(this.browserLocation.href)): Promise<void> {
    const discovery = await this.getDiscovery();
    const state = randomUrlSafe(this.cryptoApi, 32);
    const nonce = randomUrlSafe(this.cryptoApi, 32);
    const verifier = randomUrlSafe(this.cryptoApi, 64);
    const challenge = base64Url(await this.cryptoApi.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
    const pending: PendingAuthorization = { state, nonce, verifier, returnTo: safeReturnTo(returnTo) };
    this.storage.setItem(this.pendingKey, JSON.stringify(pending));
    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("redirect_uri", this.config.redirectUri);
    url.searchParams.set("scope", this.config.scope ?? "openid profile email offline_access");
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    this.browserLocation.assign(url.toString());
  }

  async logout(): Promise<void> {
    const idToken = this.session?.idToken;
    this.setSession(null);
    let destination = this.config.postLogoutRedirectUri;
    try {
      const endpoint = (await this.getDiscovery()).end_session_endpoint;
      if (endpoint) {
        const url = new URL(endpoint);
        url.searchParams.set("post_logout_redirect_uri", this.config.postLogoutRedirectUri);
        url.searchParams.set("client_id", this.config.clientId);
        if (idToken) url.searchParams.set("id_token_hint", idToken);
        destination = url.toString();
      }
    } finally {
      this.browserLocation.assign(destination);
    }
  }

  async getAccessToken(): Promise<string | undefined> {
    if (!this.session) return undefined;
    if (this.session.expiresAt > this.now() + 60_000) return this.session.accessToken;
    return (await this.refresh())?.accessToken;
  }

  private async completeAuthorization(url: URL): Promise<AuthSession | null> {
    const pending = parseJson<PendingAuthorization>(this.storage.getItem(this.pendingKey));
    this.storage.removeItem(this.pendingKey);
    const error = url.searchParams.get("error");
    if (error) throw new Error(`Sign-in failed: ${url.searchParams.get("error_description") || error}`);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    if (!pending || !code || !state || state !== pending.state) throw new Error("Sign-in response could not be verified.");
    const tokens = await this.exchange(new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: pending.verifier,
    }));
    const session = this.sessionFromTokens(tokens, undefined, pending.nonce);
    this.setSession(session);
    const returnUrl = new URL(pending.returnTo, this.config.redirectUri);
    this.browserHistory.replaceState({}, "", `${returnUrl.pathname}${returnUrl.search}${returnUrl.hash}`);
    return session;
  }

  private async refresh(): Promise<AuthSession | null> {
    const refreshToken = this.session?.refreshToken;
    if (!refreshToken) {
      this.setSession(null);
      return null;
    }
    if (this.refreshPromise) return this.refreshPromise;
    const previous = this.session!;
    this.refreshPromise = this.exchange(new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.config.clientId,
      refresh_token: refreshToken,
    })).then((tokens) => {
      const session = this.sessionFromTokens(tokens, previous);
      this.setSession(session);
      return session;
    }).catch(() => {
      this.setSession(null);
      return null;
    }).finally(() => {
      this.refreshPromise = undefined;
    });
    return this.refreshPromise;
  }

  private async exchange(body: URLSearchParams): Promise<TokenResponse> {
    const endpoint = (await this.getDiscovery()).token_endpoint;
    const response = await this.fetcher(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body,
    });
    if (!response.ok) throw new Error("The identity provider rejected the session request.");
    const value = await response.json() as Partial<TokenResponse>;
    if (!value.access_token || !Number.isFinite(value.expires_in) || Number(value.expires_in) <= 0) {
      throw new Error("The identity provider returned an invalid token response.");
    }
    if (value.token_type && value.token_type.toLowerCase() !== "bearer") throw new Error("Unsupported access token type.");
    return value as TokenResponse;
  }

  private sessionFromTokens(tokens: TokenResponse, previous?: AuthSession, expectedNonce?: string): AuthSession {
    const idToken = tokens.id_token ?? previous?.idToken;
    const claims = decodeClaims(idToken ?? tokens.access_token);
    if (expectedNonce && claims.nonce !== expectedNonce) throw new Error("Sign-in nonce did not match.");
    const organizationClaim = this.config.organizationClaim ?? "org_id";
    const organizationId = stringClaim(claims[organizationClaim]);
    if (!organizationId || organizationId !== this.config.organizationId) throw new Error("Your session does not grant access to this organization.");
    const subject = stringClaim(claims.sub);
    if (!subject) throw new Error("Your session is missing a subject identifier.");
    const rolesClaim = claims[this.config.rolesClaim ?? "roles"];
    const rawRoles = Array.isArray(rolesClaim) ? rolesClaim : typeof rolesClaim === "string" ? rolesClaim.split(" ") : [];
    const roles = normalizeRoles(rawRoles);
    const email = stringClaim(claims.email);
    const name = stringClaim(claims.name) || email || subject;
    return {
      accessToken: tokens.access_token,
      idToken,
      refreshToken: tokens.refresh_token ?? previous?.refreshToken,
      expiresAt: this.now() + Number(tokens.expires_in) * 1000,
      user: { subject, organizationId, name, email, initials: initials(name), roles },
    };
  }

  private async getDiscovery(): Promise<OidcDiscovery> {
    if (this.discovery) return this.discovery;
    const issuer = this.config.issuer.replace(/\/$/, "");
    const response = await this.fetcher(`${issuer}/.well-known/openid-configuration`, { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error("The identity provider is unavailable.");
    const value = await response.json() as Partial<OidcDiscovery>;
    if (value.issuer !== issuer || !isHttpsUrl(value.authorization_endpoint) || !isHttpsUrl(value.token_endpoint)) {
      throw new Error("The identity provider configuration is invalid.");
    }
    if (value.end_session_endpoint && !isHttpsUrl(value.end_session_endpoint)) throw new Error("The sign-out endpoint is invalid.");
    this.discovery = value as OidcDiscovery;
    return this.discovery;
  }

  private readSession(): AuthSession | null {
    const value = parseJson<AuthSession>(this.storage.getItem(this.sessionKey));
    if (!value || !value.accessToken || !Number.isFinite(value.expiresAt) || !value.user) {
      this.storage.removeItem(this.sessionKey);
      return null;
    }
    value.user.roles = normalizeRoles(value.user.roles);
    return value;
  }

  private setSession(session: AuthSession | null): void {
    this.session = session;
    if (session) this.storage.setItem(this.sessionKey, JSON.stringify(session));
    else this.storage.removeItem(this.sessionKey);
    this.listeners.forEach((listener) => listener(session));
  }
}

function decodeClaims(token: string): Record<string, unknown> {
  const part = token.split(".")[1];
  if (!part) throw new Error("The identity token is malformed.");
  try {
    const json = atob(part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "="));
    const value = JSON.parse(json) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch {
    throw new Error("The identity token is malformed.");
  }
}

function base64Url(value: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomUrlSafe(cryptoApi: Crypto, size: number): string {
  const bytes = new Uint8Array(size);
  cryptoApi.getRandomValues(bytes);
  return base64Url(bytes.buffer);
}

function currentPath(href: string): string {
  const url = new URL(href);
  return `${url.pathname}${url.search}${url.hash}`;
}

function safeReturnTo(value: string): string {
  return value.startsWith("/") && !value.startsWith("//") ? value : "/";
}

function parseJson<T>(value: string | null): T | undefined {
  if (!value) return undefined;
  try { return JSON.parse(value) as T; } catch { return undefined; }
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function normalizeRoles(values: unknown[]): AuthRole[] {
  return [...new Set(values.flatMap((value) => typeof value === "string" && ROLE_ALIASES[value] ? [ROLE_ALIASES[value]] : []))];
}

function initials(name: string): string {
  return name.split(/\s+/).filter(Boolean).slice(0, 2).map((word) => word[0]?.toUpperCase()).join("") || "AU";
}

function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try { return new URL(value).protocol === "https:"; } catch { return false; }
}
