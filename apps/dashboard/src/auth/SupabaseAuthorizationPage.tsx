import { createClient } from "@supabase/supabase-js";
import { type FormEvent, useEffect, useMemo, useState } from "react";
import { Brand } from "../components/Brand";

interface AuthorizationDetails {
  authorization_id: string;
  client: { name: string };
  scope: string;
  user: { email: string };
}

type Step = "loading" | "credentials" | "totp" | "enroll" | "consent" | "error";

export function SupabaseAuthorizationPage({ url, publishableKey }: { url: string; publishableKey: string }) {
  const client = useMemo(() => createClient(url, publishableKey), [publishableKey, url]);
  const authorizationId = new URLSearchParams(window.location.search).get("authorization_id");
  const [step, setStep] = useState<Step>("loading");
  const [error, setError] = useState<string>();
  const [factorId, setFactorId] = useState<string>();
  const [qrCode, setQrCode] = useState<string>();
  const [details, setDetails] = useState<AuthorizationDetails>();

  useEffect(() => {
    let active = true;
    void client.auth.getSession().then(({ data, error: sessionError }) => {
      if (!active) return;
      if (sessionError) return fail(sessionError);
      if (!data.session) return setStep("credentials");
      return continueAuthentication();
    });
    return () => { active = false; };
  }, [client]);

  function fail(cause: unknown) {
    setError(cause instanceof Error ? cause.message : "Authentication could not be completed.");
    setStep("error");
  }

  async function continueAuthentication() {
    try {
      const assurance = await client.auth.mfa.getAuthenticatorAssuranceLevel();
      if (assurance.error) throw assurance.error;
      if (assurance.data.currentLevel === "aal2") return loadAuthorization();
      const factors = await client.auth.mfa.listFactors();
      if (factors.error) throw factors.error;
      const verified = factors.data.totp[0];
      if (verified) {
        setFactorId(verified.id);
        setStep("totp");
        return;
      }
      const enrollment = await client.auth.mfa.enroll({
        factorType: "totp",
        friendlyName: "Actis staging",
        issuer: "Actis",
      });
      if (enrollment.error) throw enrollment.error;
      setFactorId(enrollment.data.id);
      setQrCode(enrollment.data.totp.qr_code);
      setStep("enroll");
    } catch (cause) {
      fail(cause);
    }
  }

  async function loadAuthorization() {
    if (!authorizationId) return fail(new Error("The authorization request is missing."));
    try {
      const response = await client.auth.oauth.getAuthorizationDetails(authorizationId);
      if (response.error) throw response.error;
      if ("redirect_url" in response.data) {
        window.location.assign(response.data.redirect_url);
        return;
      }
      setDetails(response.data);
      setStep("consent");
    } catch (cause) {
      fail(cause);
    }
  }

  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(undefined);
    const result = await client.auth.signInWithPassword({
      email: String(form.get("email") ?? ""),
      password: String(form.get("password") ?? ""),
    });
    if (result.error) return fail(result.error);
    await continueAuthentication();
  }

  async function verifyTotp(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!factorId) return fail(new Error("No TOTP factor is available."));
    const code = String(new FormData(event.currentTarget).get("code") ?? "");
    const result = await client.auth.mfa.challengeAndVerify({ factorId, code });
    if (result.error) return fail(result.error);
    await loadAuthorization();
  }

  async function decide(approved: boolean) {
    if (!authorizationId) return fail(new Error("The authorization request is missing."));
    const result = approved
      ? await client.auth.oauth.approveAuthorization(authorizationId)
      : await client.auth.oauth.denyAuthorization(authorizationId);
    if (result.error) fail(result.error);
  }

  return <main className="auth-screen"><section className="auth-card" aria-live="polite">
    <Brand />
    {step === "loading" ? <><h1>Preparing secure sign-in</h1><div className="auth-progress" /></> : null}
    {step === "credentials" ? <form className="auth-form" onSubmit={(event) => { void signIn(event) }}>
      <h1>Sign in to Actis</h1>
      <label>Email<input name="email" type="email" autoComplete="username" required /></label>
      <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
      <button className="button-primary" type="submit">Continue</button>
    </form> : null}
    {step === "enroll" ? <>
      <h1>Protect this account</h1>
      <p>Scan this QR code with your authenticator app, then enter its six-digit code.</p>
      {qrCode ? <img className="auth-qr" src={qrCode} alt="TOTP enrollment QR code" /> : null}
      <TotpForm submit={verifyTotp} label="Finish enrollment" />
    </> : null}
    {step === "totp" ? <><h1>Verify your identity</h1><p>Enter the current code from your authenticator app.</p><TotpForm submit={verifyTotp} label="Verify" /></> : null}
    {step === "consent" && details ? <>
      <h1>Continue to {details.client.name}</h1>
      <p>Signed in as {details.user.email}. This first-party Actis client requests: {details.scope.split(" ").join(", ")}.</p>
      <div className="inline-actions">
        <button className="button-primary" onClick={() => { void decide(true) }}>Continue</button>
        <button className="button" onClick={() => { void decide(false) }}>Cancel</button>
      </div>
    </> : null}
    {step === "error" ? <><h1>Sign-in could not be completed</h1><p role="alert">{error}</p><button className="button-primary" onClick={() => window.location.reload()}>Try again</button></> : null}
  </section></main>;
}

function TotpForm({ submit, label }: { submit(event: FormEvent<HTMLFormElement>): Promise<void>; label: string }) {
  return <form className="auth-form" onSubmit={(event) => { void submit(event) }}>
    <label>Authentication code<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" required /></label>
    <button className="button-primary" type="submit">{label}</button>
  </form>;
}
