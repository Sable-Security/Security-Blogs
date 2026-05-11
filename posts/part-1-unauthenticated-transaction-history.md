# Your Users' Bank Account Numbers Were One API Call Away

We typed a single URL into a terminal. No login. No token. No session cookie. What came back was the complete financial history of a real person — every crypto purchase, every fiat amount, every exchange rate, and in some cases, their bank IBAN. We did this for multiple users in under a minute, using only wallet addresses that are publicly visible on Ethereum's blockchain.

This wasn't a sophisticated attack. It was a missing `@UseGuards()` decorator on a handful of API endpoints.

## What We Were Looking At

The target was a European cryptocurrency exchange platform — the kind that lets retail customers convert fiat money into crypto and back. It handles real bank transfers, KYC-verified identities, and tax reporting exports. Its users trust it with some of the most sensitive financial data they have. The platform is built on a modern TypeScript/NestJS backend, the kind of clean, well-structured codebase that most developers would be proud of — which made this finding more striking, not less.

## The Finding

The platform exposed six endpoints under `/v1/transaction` with no authentication guards at all. These weren't obscure admin routes. They were the primary history and tax export endpoints — the ones users rely on for their CoinTracking imports and annual tax filings. Any of them accepted a `userAddress` query parameter and returned data for whoever that address belonged to, no token required.

```typescript
// What the controller actually looked like:
@Get()
@ApiOkResponse({ type: TransactionDto, isArray: true })
async getTransactions(
  @Query() query: HistoryQueryUser,
  @Res({ passthrough: true }) res: Response,
): Promise<TransactionDto[] | StreamableFile> {
  return this.getHistoryData(query, ExportType.COMPACT, res);
}

// What it should have looked like:
@Get()
@ApiBearerAuth()
@UseGuards(AuthGuard(), RoleGuard(UserRole.ACCOUNT))
async getTransactions(
  @GetJwt() jwt: JwtPayload,   // pull the user from the token, not the URL
  @Query() query: HistoryQuery,
  @Res({ passthrough: true }) res: Response,
): Promise<TransactionDto[] | StreamableFile> {
  return this.getHistoryData(query, ExportType.COMPACT, res);
}
```

The contrast was sharp: the adjacent `/detail` endpoints correctly applied `@UseGuards(AuthGuard(), RoleGuard(UserRole.ACCOUNT))`. The transaction history endpoints were simply missing those decorators. One of those small things that gets skipped during a late-night feature push and never caught in code review because the feature worked correctly for the developer testing it — they were authenticated when they tested it.

The blockchain address prerequisite sounds like a mitigating factor until you think about it for ten seconds. Ethereum addresses are public by design. Every user who has ever transacted with the platform has sent funds to the platform's known deposit addresses — and those senders' addresses are permanently on-chain, queryable from Etherscan's public API in bulk. An attacker could enumerate tens of thousands of platform users' complete financial histories with a simple loop.

## The Impact

Each transaction record exposed the fiat amount paid, the crypto asset received, the exchange rate at the time, exact timestamps, fees, and the blockchain transaction ID. For chargeback transactions, the response also included the user's bank IBAN — personally identifiable financial information under GDPR. The tax export endpoints (CoinTracking, ChainReport) returned the most comprehensive version of this data, since they're designed for exactly that: a complete, structured record of everything.

An attacker who pulled this data at scale could profile users by trading volume to target high-value accounts, use transaction patterns for highly specific phishing, or simply sell the dataset. The IBAN exposure alone triggers mandatory breach notification obligations. If this had been found by someone other than a security researcher, the platform's first indication might have been a support queue full of users who never contacted support — accounts cleaned out through targeted fraud.

## The Fix

Add authentication guards to every transaction history endpoint. The `userAddress` query parameter should be removed entirely — the user identity should come from the authenticated JWT, not from a URL parameter an attacker can set to anything.

```typescript
// Remove the userAddress query param. Replace with JWT identity.
@Get()
@ApiBearerAuth()
@UseGuards(AuthGuard(), RoleGuard(UserRole.ACCOUNT))
async getTransactions(
  @GetJwt() jwt: JwtPayload,
  @Query() query: HistoryQuery,
  @Res({ passthrough: true }) res: Response,
): Promise<TransactionDto[] | StreamableFile> {
  // query now contains no userAddress — the service resolves it from jwt.accountId
  return this.getHistoryData({ ...query, accountId: jwt.account }, ExportType.COMPACT, res);
}
```

The fixed behavior: a user can only retrieve their own history. An unauthenticated request returns 401. A request with a valid token for user A cannot retrieve user B's records — the account is bound to the token, not to a parameter.

## The Pattern

This vulnerability class — missing authorization on read endpoints — is one of the most common findings in startup codebases. The reason it happens isn't carelessness. It's that read endpoints feel lower-stakes than write endpoints during development. There's no "delete" in the route name, no mutation visible, no danger that feels immediate when you're shipping. Authentication guards get added to the endpoints that feel dangerous. The history export endpoint — which is only showing data, after all — gets deprioritized.

Open every controller in your NestJS (or equivalent) application right now. Search for `@Get()` decorators. For each one: does it have `@UseGuards(AuthGuard())`? If not, what does it return, and who is supposed to be able to see that? If the answer isn't "everyone," the guard is missing.

---

*If you want to know whether your app has this before an attacker does, we'll scan one endpoint for free — no strings.*

---

**Technical appendix:** CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5 High** | CWE-306 (Missing Authentication for Critical Function)
