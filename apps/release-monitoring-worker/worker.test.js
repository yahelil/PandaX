import assert from "node:assert/strict";
import test from "node:test";

import { triggerMonitoring } from "./worker.js";

test("calls the private scheduler endpoint with its bearer secret", async () => {
  let request;
  const result = await triggerMonitoring(
    {
      PANDAX_API_URL: "https://api.example.test/ignored/path",
      PANDAX_SCHEDULER_SECRET: "x".repeat(32),
    },
    async (url, init) => {
      request = { url: String(url), init };
      return new Response(JSON.stringify({ status: "completed", claimed: 1 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  );

  assert.equal(request.url, "https://api.example.test/internal/jobs/release-monitoring");
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.headers.authorization, `Bearer ${"x".repeat(32)}`);
  assert.equal(result.claimed, 1);
});

test("rejects insecure API URLs before making a request", async () => {
  await assert.rejects(
    triggerMonitoring({
      PANDAX_API_URL: "http://api.example.test",
      PANDAX_SCHEDULER_SECRET: "x".repeat(32),
    }),
    /must use HTTPS/,
  );
});

test("surfaces an API failure without retrying", async () => {
  let calls = 0;
  await assert.rejects(
    triggerMonitoring(
      {
        PANDAX_API_URL: "https://api.example.test",
        PANDAX_SCHEDULER_SECRET: "x".repeat(32),
      },
      async () => {
        calls += 1;
        return new Response("unavailable", { status: 503 });
      },
    ),
    /HTTP 503/,
  );
  assert.equal(calls, 1);
});
