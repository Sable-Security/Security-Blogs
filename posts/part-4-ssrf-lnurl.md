# We Made a Crypto Exchange's Server Talk to Its Own Internal Network

The endpoint was for registering a Lightning wallet. We didn't have an account. We sent it a URL — encoded in a format the server expected — pointing to the cloud instance metadata service at `169.254.169.254`. The server made an outbound TCP connection to that address and waited. We watched the request hang for 135 seconds. That's how long it took the connection to time out. That's also how long it took us to confirm the server was reaching into its own infrastructure on our behalf.

We never saw the response. We didn't need to. The timing told us everything.

## What We Were Looking At

The same European crypto exchange platform we've been covering in this series. The Lightning Network integration allows users to register Lightning wallet addresses for sending and receiving crypto. The registration flow needs to resolve the wallet's public key — so when a new user signs up with a Lightning address, the server makes an HTTP request to that address to fetch cryptographic wallet metadata. This is normal Lightning Network behavior. The problem was that the server fetched whatever URL the address decoded to, with no checks on where that URL pointed.

## The Finding

Lightning Network uses a format called LNURL — a bech32-encoded URL that wallets decode to find payment endpoints. The server's `getInvoiceByLnurlp()` function decoded the LNURL and immediately fired an HTTP GET to the resulting address:

```typescript
async getInvoiceByLnurlp(lnurlpAddress: string, amount?: number): Promise<string> {
  const lnurlpUrl = LightningHelper.decodeLnurl(lnurlpAddress);
  // ↑ Decodes bech32 → raw URL string. No protocol check. No IP range check.

  const payRequest = await this.http.get<LnurlPayRequestDto>(lnurlpUrl);
  // ↑ Server fetches whatever URL we encoded. SSRF.

  return this.http.get<LnurlpInvoiceDto>(payRequest.callback, { params: { amount } });
  // ↑ Then follows the `callback` field from the first response. Second SSRF.
}
```

LNURL is just bech32 encoding. Any URL can be encoded in it. We encoded `http://169.254.169.254/metadata/instance` — the Azure Instance Metadata Service endpoint that returns cloud credentials for VMs with Managed Identity enabled — and submitted it as a wallet address to the unauthenticated registration endpoint. The server decoded it and made the request.

The response always came back as a 400 error — the server couldn't complete the Lightning handshake because our targets weren't Lightning servers. But the server had already made the outbound connection before returning that error. We measured response times across a range of internal targets:

| Target | Response Time | What It Means |
|---|---|---|
| `127.0.0.1:80` (closed) | 0.76s | Immediate RST — port not open |
| `127.0.0.1:1433` (MSSQL) | 1.55s | TCP connection reached a service |
| `10.0.0.1` (internal gateway) | ~6s | Server reached its internal network |
| `169.254.169.254` (cloud metadata) | **135s** | Full TCP timeout — server connected to IMDS |

A 135-second wait is not a coincidence. That's the server holding an open TCP connection to the cloud metadata service, waiting for data that never arrives in the right format. The platform's internal MSSQL database port showed elevated response time — consistent with an open port on localhost. We found the internal gateway by measuring the 6-second timeout characteristic of filtered internal routes.

The second SSRF in the code path made it potentially chainable: if an attacker controlled a server that returned a valid JSON response with a `callback` field pointing to an internal target, the platform's server would follow that URL for a second request — letting an attacker use their own server as a proxy to reach internal services.

## The Impact

At its most basic level, this is a port scanner for the platform's internal infrastructure, operable by anyone on the internet with no account. By systematically varying IP addresses and ports and measuring response times, an attacker maps which services are running inside the network — databases, caches, internal admin dashboards, orchestration APIs. Services that aren't exposed to the internet are still reachable through the server as a proxy.

If the platform runs on a cloud provider with Managed Identity enabled — common in Azure, AWS, and GCP deployments — the `169.254.169.254` endpoint returns short-lived credentials for the server's cloud identity. Those credentials could be used to access cloud storage, secret managers, and management APIs. The platform manages customer crypto payouts, so the cloud identity almost certainly has access to production infrastructure.

If an attacker controls a domain that resolves to `169.254.169.254` (DNS rebinding), the same attack works without the IP filter that some cloud providers apply. The second SSRF via `callback` extends the reach further.

## The Fix

Validate the decoded URL before making any outbound request. Reject non-HTTPS URLs, private IP ranges (RFC1918: `10.x.x.x`, `172.16.x.x-172.31.x.x`, `192.168.x.x`), link-local addresses (`169.254.x.x`), and localhost (`127.x.x.x`):

```typescript
async getInvoiceByLnurlp(lnurlpAddress: string, amount?: number): Promise<string> {
  const lnurlpUrl = LightningHelper.decodeLnurl(lnurlpAddress);

  const url = new URL(lnurlpUrl);
  if (url.protocol !== 'https:') {
    throw new BadRequestException('LNURL must use HTTPS');
  }
  if (isPrivateIp(url.hostname)) {
    throw new BadRequestException('LNURL must not point to an internal address');
  }

  const payRequest = await this.http.get<LnurlPayRequestDto>(lnurlpUrl);

  // Apply the same validation to the callback URL before following it
  const callbackUrl = new URL(payRequest.callback);
  if (callbackUrl.protocol !== 'https:' || isPrivateIp(callbackUrl.hostname)) {
    throw new BadRequestException('Invalid callback URL');
  }

  return this.http.get<LnurlpInvoiceDto>(payRequest.callback, { params: { amount } });
}
```

Use a library like `is-private-ip` or implement the RFC1918 ranges explicitly. After validation, the server should only ever make outbound requests to public HTTPS addresses that it decoded from the LNURL — never to internal hosts, never over plain HTTP.

## The Pattern

SSRF (Server-Side Request Forgery) hides inside any feature where your server fetches a URL on a user's behalf. Webhooks. Link previews. Import-from-URL. Payment callbacks. Avatar image fetchers. OAuth redirect validators. Anywhere your server takes a URL as input and makes an HTTP request with it, the question is the same: what happens if that URL points to `169.254.169.254`?

Pick one feature in your product that makes outbound HTTP requests based on user-supplied input. Trace the code. Find where the URL is first used in an HTTP call. Is there a validation step between the input and the request? If not — that's the finding. Fix it before someone else does the timing test.

---

*If you want to know whether your app has this before an attacker does, we'll scan one endpoint for free — no strings.*

---

**Technical appendix:** CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N` = **9.3 Critical** | CWE-918 (Server-Side Request Forgery)
