import { createContext, type PropsWithChildren, useContext, useEffect, useMemo, useState } from "react";
import type { AuthClient, AuthSession, AuthUser } from "./oidcClient";

type AuthStatus = "loading" | "authenticated" | "unauthenticated" | "error";

interface AuthContextValue {
  mode: "demo" | "connected" | "production";
  status: AuthStatus;
  user?: AuthUser;
  error?: string;
  login(): Promise<void>;
  logout(): Promise<void>;
}

const LOCAL_DEV_USER: AuthUser = {
  subject: "member-jane-doe",
  email: "jane@example.com",
  name: "Jane Doe",
  initials: "JD",
  roles: ["org_admin", "compliance_operator", "authorized_approver", "read_only_auditor"],
  organizationId: "org-acme-devices",
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ mode, client, children }: PropsWithChildren<{ mode: "demo" | "connected" | "production"; client?: AuthClient }>) {
  const isLocalOrDemo = mode === "demo" || mode === "connected";
  const [session, setSession] = useState<AuthSession | null>(
    mode === "connected"
      ? {
          user: LOCAL_DEV_USER,
          accessToken: "dev-token",
          expiresAt: Date.now() + 86400000,
        }
      : null
  );
  const [status, setStatus] = useState<AuthStatus>(isLocalOrDemo ? "authenticated" : "loading");
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (mode === "demo" || mode === "connected") return;
    if (!client) {
      setStatus("error");
      setError("Production authentication is not configured.");
      return;
    }
    let active = true;
    const unsubscribe = client.subscribe((next) => {
      if (!active) return;
      setSession(next);
      setStatus(next ? "authenticated" : "unauthenticated");
    });
    void client.initialize().then((next) => {
      if (!active) return;
      setSession(next);
      setStatus(next ? "authenticated" : "unauthenticated");
    }).catch((cause: unknown) => {
      if (!active) return;
      setStatus("error");
      setError(cause instanceof Error ? cause.message : "Sign-in could not be completed.");
    });
    return () => { active = false; unsubscribe(); };
  }, [client, mode]);

  useEffect(() => {
    if (!client || !session) return;
    const delay = Math.max(0, session.expiresAt - Date.now() - 60_000);
    const timer = window.setTimeout(() => { void client.getAccessToken(); }, delay);
    return () => window.clearTimeout(timer);
  }, [client, session]);

  const value = useMemo<AuthContextValue>(() => ({
    mode,
    status,
    user: session?.user,
    error,
    login: async () => {
      if (!client) return;
      setError(undefined);
      await client.login();
    },
    logout: async () => {
      if (!client) return;
      await client.logout();
    },
  }), [client, error, mode, session?.user, status]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used within AuthProvider.");
  return value;
}
