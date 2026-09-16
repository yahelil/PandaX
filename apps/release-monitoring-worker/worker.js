export async function triggerMonitoring(env, fetchImpl = fetch) {
  const base = new URL(env.PANDAX_API_URL);
  if (base.protocol !== "https:") {
    throw new Error("PANDAX_API_URL must use HTTPS");
  }
  if (!env.PANDAX_SCHEDULER_SECRET || env.PANDAX_SCHEDULER_SECRET.length < 32) {
    throw new Error("PANDAX_SCHEDULER_SECRET must contain at least 32 characters");
  }
  const endpoint = new URL("/internal/jobs/release-monitoring", base);
  const response = await fetchImpl(endpoint, {
    method: "POST",
    headers: { authorization: `Bearer ${env.PANDAX_SCHEDULER_SECRET}` },
  });
  if (!response.ok) {
    throw new Error(`release monitoring scheduler returned HTTP ${response.status}`);
  }
  return response.json();
}

export default {
  scheduled(_event, env, context) {
    context.waitUntil(triggerMonitoring(env));
  },
};
