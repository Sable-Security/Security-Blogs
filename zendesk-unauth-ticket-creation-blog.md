# Anyone Could File a Support Ticket as Your Company

One curl command. No session cookie, no API key, no account. We sent a POST request to a support portal's ticket creation endpoint and got back a JSON object with a live ticket ID, sitting in a real production support queue, ready for a human agent to read and act on. We did it again on a second portal. Then a third. Same org, sequential IDs — and between our test tickets, real seller support requests were flowing in from real users. We could see the gaps.

## What We Were Looking At

The target is a major e-commerce platform's Taiwan operations, running several Zendesk-powered support portals: a developer API portal, a seller marketplace help center, a general consumer help center, and — most critically — an intellectual property rights portal where counterfeit product complaints and IP enforcement requests are processed. All six portals share a single Zendesk organization. Ticket IDs are sequential across the entire org. Whatever gets submitted to any portal lands in the same queue.

## The Finding

Zendesk's `/api/v2/requests.json` endpoint handles ticket creation. By default, Zendesk allows public ticket submission on portals that are intended to be accessible to unauthenticated users — customer-facing help centers are a common use case. The problem is that B2B portals, seller portals, and developer portals are not the same thing as a consumer help center. They handle sensitive onboarding data, business credentials, and — in the case of the IPR portal — legal enforcement requests. None of them required any authentication to submit a ticket.

```bash
# No session, no token, no account — works on all six portals
curl -s -X POST "https://[redacted-portal].zendesk.com/api/v2/requests.json" \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "subject": "Test subject",
      "comment": { "body": "Test body" },
      "requester": { "name": "Any Name", "email": "any@example.com" }
    }
  }'
```

The response came back with a real ticket ID, status `new`, and confirmation of its place in the live queue. Across six portals, every single one returned HTTP 201. The sequential IDs told us something else: in the time between our first and second test tickets, approximately fourteen real seller and developer support requests had been submitted by legitimate users. Those tickets contain whatever real people submit to a business support system — API credentials, vendor IDs, business documentation, account details.

The ticket form inventory was also publicly readable without authentication. Among the forms: "Supplier | Basic information" and "Supplier | Product onboarding training" — structured onboarding forms for new supplier registration, submittable by anyone.

## The Impact

The direct consequence is support queue injection. Any actor on the internet can file unlimited tickets into the company's live seller, developer, and supplier support queues. Each ticket triggers an outbound email notification from the company's official support domain. This enables three distinct attacks from a single capability.

The first is operational disruption: flood the queue with noise and legitimate seller issues get buried. Support agents spend time triaging junk while real problems — API outages, account suspensions, payment holds — wait. The second is agent manipulation: a convincing fake ticket ("Seller account blocked — please reset API credentials to X") routes through official channels and is handled by a real human who has no reliable way to distinguish a legitimate submission from an injected one. The third is outbound phishing: by setting `requester.email` to any target address, an attacker causes the company's own official support system to send emails to that target, giving social engineering attacks a legitimate-domain cover that is genuinely difficult to detect.

The IPR portal compounds this further. IP enforcement and counterfeit complaint workflows involve real-world consequences — takedowns, account suspensions, legal notifications. An attacker who can inject fake IP complaints into that system can cause those consequences to fall on legitimate sellers or product listings without ever touching the underlying platform.

## The Fix

The root cause is a Zendesk configuration decision, not a code change. Zendesk provides per-portal controls for who can submit tickets — the options range from fully open to requiring a verified account. B2B portals, seller portals, developer portals, and any portal handling sensitive operational or legal workflows should require authentication before accepting ticket submissions. This is a settings change, not an engineering project:

In the Zendesk admin panel, navigate to **Guide Settings** for each portal and set **"Who can submit requests"** to require sign-in. For APIs accessed programmatically (developer portals, partner integrations), additionally enable **API token or OAuth authentication** on the Zendesk API settings page and remove anonymous access entirely.

The specific configuration that should be in place for any sensitive portal:

```
Zendesk Guide Settings → Ticket Submission:
  ✓ Require sign-in to submit requests
  ✓ Restrict ticket forms to authenticated users only

Zendesk API Settings:
  ✓ Token access: enabled
  ✗ Anonymous ticket creation: disabled
  ✓ Require authentication for /api/v2/requests.json
```

For supplier onboarding forms specifically, authentication is table-stakes. The forms collect business registration data that feeds internal supplier management workflows. Unauthenticated submission means those workflows can be seeded with fraudulent records at will.

## The Pattern

This misconfiguration is everywhere. Zendesk's defaults are optimized for consumer help centers — the broadest possible access so customers can always get support. When companies deploy the same Zendesk org across multiple portals with different trust levels, the consumer defaults follow. Nobody goes back and tightens the configuration on the developer portal or the seller portal because those portals "work," and working is the bar most teams measure against. Right now, if your company runs a Zendesk and that Zendesk powers more than one portal, open each portal's settings and check who is allowed to submit tickets. If any of those portals touch business operations, legal workflows, or partner data and the answer is "anyone," you have this finding.

---

If you want to know whether your app has this before an attacker does, we'll scan one endpoint for free — no strings.

---

**Technical Appendix**
CVSS Score: 6.5 | CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
CWE-306 (Missing Authentication for Critical Function), CWE-284 (Improper Access Control)
