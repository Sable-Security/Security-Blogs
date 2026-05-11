# One Null Field. Full Account Takeover. Victim Permanently Locked Out.

The authentication check was there. The cryptographic verification logic was written. The code looked correct at a glance. The problem was a single `!` operator in a condition that had been quietly handling certain accounts wrong for months — accounts where a database field was `null` instead of a real value. For those accounts, the server accepted any 140-character hex string as valid credentials. No knowledge of the real key required.

We found a Lightning wallet address, sent a fake signature made of repeating `a1`, and received a valid JWT for the account. Then we noticed the side effect: the platform had just overwritten the real user's stored signature with our fake one. The legitimate user could no longer log in.

## What We Were Looking At

The target was the same European crypto exchange platform discussed in our previous post — one that handles real fiat-to-crypto transactions for retail users, with KYC verification, linked bank accounts, and Lightning Network integration. Lightning support was a relatively recent addition to the platform, introduced in a batch of new functionality a few months before we tested it. The Lightning authentication flow was separate from the standard wallet flows — and that separation is where the gap opened up.

## The Finding

Lightning wallet authentication on this platform uses a cryptographic signature to verify that the user controls the wallet address they're claiming. The `verifySignature()` function handles this check. The vulnerable condition was a single boolean expression:

```typescript
// Vulnerable:
return !dbSignature || signature === dbSignature;
//     ^^^^^^^^^^^
//     If dbSignature is null in the database:
//     !null === true → returns true, no crypto check performed
```

The function received `dbSignature` — the signature stored for this user in the database — and the attacker-supplied `signature`. If no stored value existed (`null`), the logic treated that as "nothing to compare against, so any input passes." Combined with a regex that matched the custodial Lightning signature format for any caller — not just internal custodial flows — the bypass was reachable from any unauthenticated POST request.

The codebase even documented that null-signature accounts existed in production. A TODO comment in `doSignIn()` described a "temporary" migration shim that updates null signatures on login — and hadn't been removed:

```typescript
} else if (!user.signature) {
  // TODO: temporary code to update empty signatures (remove?)
  await this.userRepo.update({ address: dto.address }, { signature: dto.signature });
}
```

That migration shim is also what made the lockout permanent. On a successful bypass, this code ran — writing our fake hex string to the database as the new stored signature. The real user's next login attempt compared their actual cryptographic signature against our fake value, got a mismatch, and received 401.

The fix is a one-character change. Flipping `!dbSignature || ...` to `!!dbSignature && ...` means accounts with no stored signature are rejected rather than silently accepted:

```typescript
// Fixed:
return !!dbSignature && signature === dbSignature;
// If dbSignature is null: !!null === false → returns false → 401
```

## The Impact

A successful bypass produced a valid JWT with the victim's full account identity: their KYC-verified name, email, linked bank IBANs, wallet addresses, and complete transaction history. That's the same access level as the legitimate user — not a partial read, not a limited view. The attacker could initiate withdrawals, modify account settings, and read everything in the account.

The lockout effect made it worse. The platform generated no alert, no email, no 2FA prompt when a custodial-format signature was used. The victim had no indication their account had been accessed until they tried to log in themselves and found their credentials no longer worked. Recovery required manual database intervention by platform staff.

Chained with the unauthenticated transaction history endpoint described in our previous post, the attack became scalable: enumerate Lightning wallet addresses from the transaction API, scan them against the auth endpoint, identify every null-signature account in the database, and take them over in sequence.

## The Fix

The one-line fix above addresses the bypass. Beyond that, the migration shim needs to go. Any Lightning accounts still carrying null signatures should be forced through an explicit recovery flow — not silently "fixed" by accepting whatever signature the next request happens to send.

```typescript
// Remove this block entirely:
} else if (!user.signature) {
  // TODO: temporary code to update empty signatures (remove?)
  await this.userRepo.update({ address: dto.address }, { signature: dto.signature });
}
```

Null-signature accounts should be identified with a database query and handled proactively — either by prompting re-registration or by an internal key rotation process. Leaving the window open "temporarily" for months is how temporary becomes permanent.

## The Pattern

Migration shims and TODO comments in authentication code are a specific category of risk that deserves its own checklist item. Code that was "temporary" six months ago is now load-bearing. The developer who wrote it left a note to remove it. Nobody did. The system depended on that shim not being exploited during the migration window — but migration windows that never close aren't windows, they're doors.

Search your codebase for `TODO` comments in authentication, authorization, and session handling code. Each one is a known technical debt item in the most sensitive part of your stack. If it's been there longer than two weeks, treat it as a bug, file a ticket with a due date, and own it.

---

*If you want to know whether your app has this before an attacker does, we'll scan one endpoint for free — no strings.*

---

**Technical appendix:** CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L` = **7.5 High** | CWE-287 (Improper Authentication)
