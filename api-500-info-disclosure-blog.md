# The Endpoint That Couldn't Stop Talking About Itself

We hit a documented production endpoint and got back a 500 error. That happens. We hit it again. Same error. Five more times — same error, same structure, different timestamp each time. The endpoint was not crashing intermittently. It was broken, consistently, every single request, and every response was carefully telling us exactly why that was interesting: the backend runtime, the deployment platform, the cloud region, the internal route name, and a live server timestamp we could use to correlate logs. A broken feature had become an information feed.

## What We Were Looking At

The target is a DeFi protocol built around a Swiss franc-pegged stablecoin. Its public API exposes analytics endpoints intended to give users, auditors, and third-party integrators access to transaction history and protocol data. These are not obscure internal routes — they appear in the platform's publicly accessible Swagger/OpenAPI documentation, meaning they are explicitly advertised as production features. For a DeFi protocol, transaction log access is a transparency commitment. When it breaks, people notice. When it breaks and leaks infrastructure details, the people who notice include attackers.

## The Finding

The two affected endpoints — `/analytics/transactionLog/json` and `/analytics/transactionLog/csvE18` — return HTTP 500 on every request with no authentication required and no special parameters needed. The failure is not transient. Calling either endpoint ten times returns the same error ten times, with a fresh timestamp each time confirming the server is processing the request and failing at runtime, not returning a cached error page.

The response body is a structured JSON error object:

```json
{
  "statusCode": 500,
  "error": "InternalServerError",
  "message": "Internal server error",
  "timestamp": "2026-05-06T02:06:05.187Z",
  "path": "/analytics/transactionLog/json"
}
```

And the response headers add more:

```
X-Powered-By: Express
Server: railway-edge
X-Railway-Edge: railway/asia-southeast1-eqsg3a
X-Railway-Request-Id: b0LNklNCSdq1F4aS-8Y8hA
```

In four lines of headers and one JSON object, an unauthenticated caller learns the backend runs Node.js with Express, the service is deployed on Railway, the infrastructure region is Singapore (`asia-southeast1-eqsg3a`), and the platform uses internal request tracing with IDs exposed to the public internet. None of this was meant to be shared.

The underlying cause is almost certainly a broken dependency in the analytics pipeline — a missing database connection, a failed aggregation query, or a data source that was never properly wired up. Whatever the root cause, the Express application has no global error handler catching it, so the unhandled exception bubbles up and the framework's default error formatter sends everything it knows back to the client.

## The Impact

The direct business impact is a broken feature. Transaction log access is how DeFi protocols demonstrate transparency. Auditors and integrators who call these endpoints get nothing — just errors. That is a credibility problem independent of security.

The security impact layers on top. Knowing the backend is Express on Railway in Singapore is reconnaissance. It tells an attacker which cloud provider's support line to target in a social engineering attempt, which platform's known vulnerabilities to research, and roughly where the infrastructure lives. The `X-Railway-Request-Id` header is an internal tracing identifier — exposed to any caller, it gives an attacker a correlation handle for probing timing patterns or infrastructure behavior. The live timestamp in every error response makes that worse: an attacker can use it to align their own logs with server-side events, narrowing down the timing of other requests or deployments.

The longer-tail risk is error-based extraction. Right now the error message is generic. If the analytics query ever starts including user-supplied parameters — a wallet address, a date range, a filter — and the error message ever reflects those parameters back, the endpoint becomes a channel for extracting information about what the database contains based on how queries fail. That is not hypothetical; it is a standard secondary risk whenever error responses are structurally rich and uncontrolled.

## The Fix

There are two problems here and they need separate fixes.

The first is the broken endpoint itself. The right answer is to find the root cause — the failed database connection or data aggregation dependency — and fix it. While that work is underway, the endpoint should return a 503 Service Unavailable with a clean message rather than letting the unhandled exception produce a 500 that leaks internals:

```javascript
// VULNERABLE — unhandled exception produces verbose 500 with internals
// (no error handler; Express default formatter sends path, timestamp, stack info)

// FIXED — temporary placeholder until the underlying issue is resolved
app.get('/analytics/transactionLog/json', (req, res) => {
  res.status(503).json({ error: 'This endpoint is temporarily unavailable.' });
});

// FIXED — global error handler for all unhandled exceptions
app.use((err, req, res, next) => {
  console.error(err); // log internally — full detail, not visible to clients
  res.status(500).json({ error: 'Internal Server Error' });
  // Do NOT include: timestamp, path, err.message, stack traces, internal route names
});
```

The second is the header leakage. Express exposes the runtime by default with `X-Powered-By`. Railway exposes routing infrastructure through its own headers. Both should be stripped at the application or reverse proxy layer:

```javascript
// Remove Express runtime disclosure — one line, global effect
app.disable('x-powered-by');

// Railway headers (X-Railway-Edge, X-Railway-Request-Id) should be
// suppressed in Railway's configuration or stripped at the CDN/proxy layer
```

Once both fixes are in place, a broken endpoint should return an opaque error that tells a caller only what they need to know: the service is unavailable. Nothing about why, where, or how it runs.

## The Pattern

This finding is what happens when error handling is an afterthought. Every framework has default error behavior, and the defaults are designed for developer convenience — verbose, structured, full of context — not for production security. Teams ship with the defaults because the application works and errors are edge cases. Then an edge case becomes permanent, and the verbose default runs on every request indefinitely. Right now, the one action to take: search your codebase for your framework's default error handler and verify you have a global override in place that strips internal details before responding. In Express, look for `app.use((err, req, res, next) =>`. In other frameworks, find the equivalent. If it is not there, add it before you ship anything else.

---

If you want to know whether your app has this before an attacker does, we'll scan one endpoint for free — no strings.

---

**Technical Appendix**
CVSS Score: 5.3 | CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L
CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-390 (Detection of Error Condition Without Action), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
