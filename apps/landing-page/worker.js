/**
 * The site is static. This exists for one route: the contact form, so a
 * visitor's message reaches us instead of opening their mail client and
 * hoping they finish the job.
 *
 * Everything else is handed straight back to the asset server.
 *
 * Configuration (Worker secrets, set once):
 *   RESEND_API_KEY   an API key from the mail provider
 *   CONTACT_TO       where the message should land
 *   CONTACT_FROM     optional; a verified sender on that key's domain
 *
 * Without those the route answers 503 and the page falls back to mailto,
 * so an unconfigured deploy degrades rather than swallowing messages.
 */

const LIMIT = 4000;
const FIELDS = ["name", "email", "company", "message", "kind"];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/contact") {
      if (request.method !== "POST") return json({ ok: false, error: "method" }, 405);
      return contact(request, env);
    }
    return env.ASSETS.fetch(request);
  },
};

async function contact(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "bad_request" }, 400);
  }
  if (!body || typeof body !== "object") return json({ ok: false, error: "bad_request" }, 400);

  // The honeypot. A person never sees this field, so anything in it is a bot.
  // Answered as success: telling a bot it failed only teaches it to retry.
  if (trim(body.company_url)) return json({ ok: true });

  const f = {};
  for (const k of FIELDS) f[k] = trim(body[k]);
  if (!f.name || !f.email) return json({ ok: false, error: "missing" }, 422);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(f.email)) return json({ ok: false, error: "email" }, 422);

  const key = env.RESEND_API_KEY;
  const to = env.CONTACT_TO;
  if (!key || !to) return json({ ok: false, error: "not_configured" }, 503);

  const lines = [
    `Name:    ${f.name}`,
    `Email:   ${f.email}`,
    `Company: ${f.company || ","}`,
    `Form:    ${f.kind || ","}`,
    "",
    f.message || "(no message)",
  ];

  let sent;
  try {
    sent = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify({
        from: env.CONTACT_FROM || "PandaX site <onboarding@resend.dev>",
        to: [to],
        reply_to: f.email,
        subject: `pandax.online, ${f.name}${f.company ? ` (${f.company})` : ""}`,
        text: lines.join("\n"),
      }),
    });
  } catch {
    return json({ ok: false, error: "unreachable" }, 502);
  }
  if (!sent.ok) return json({ ok: false, error: "send_failed" }, 502);
  return json({ ok: true });
}

function trim(v) {
  return typeof v === "string" ? v.trim().slice(0, LIMIT) : "";
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
