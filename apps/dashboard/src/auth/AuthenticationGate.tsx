import type { PropsWithChildren } from "react";
import { Brand } from "../components/Brand";
import type { TeamMember } from "../data/types";
import { useAuth } from "./AuthProvider";
import type { AuthUser } from "./oidcClient";

export function AuthenticationGate({ children }: PropsWithChildren) {
  const auth = useAuth();
  if (auth.mode === "demo" || auth.status === "authenticated") return children;
  return <main className="auth-screen">
    <section className="auth-card" aria-live="polite">
      <Brand />
      {auth.status === "loading" ? <><h1>Restoring your session</h1><p>Confirming secure access to your Actis workspace.</p><div className="auth-progress" /></> : null}
      {auth.status === "unauthenticated" ? <><h1>Sign in to Actis</h1><p>Use your organization account to continue to product security and compliance operations.</p><button className="button-primary" onClick={() => { void auth.login() }}>Sign in</button></> : null}
      {auth.status === "error" ? <><h1>Sign-in could not be completed</h1><p role="alert">{auth.error}</p><button className="button-primary" onClick={() => { void auth.login() }}>Try again</button></> : null}
    </section>
  </main>;
}

export function authenticatedTeamMember(user: AuthUser | undefined): TeamMember | undefined {
  if (!user) return undefined;
  return {
    id: user.subject,
    name: user.name,
    email: user.email ?? "",
    title: "Actis member",
    initials: user.initials,
    roles: user.roles,
    status: "active",
  };
}
