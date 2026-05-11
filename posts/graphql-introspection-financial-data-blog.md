# How a Default GraphQL Setting Exposed Sensitive Crypto Financial Data

We sent a single HTTP request. No credentials. No special tooling. Just a standard GraphQL introspection query — the kind that ships enabled by default in every major GraphQL framework — and the server handed us a complete map of its own data model: 138 types, every queryable field, every relationship. Then we started asking questions. Within minutes we had the exact balances of 7,065 wallets, the top account holding over $1.2 million in the platform's stablecoin, and a feed of private transaction notes — loan terms, salary payments, business memos — written by real users who had no idea anyone could read them.

Nobody had to break anything. The front door was open.

## What We Were Looking At

The target was a DeFi (decentralized finance) stablecoin platform: a web3 financial application that lets users mint, hold, transfer, and earn yield on a Swiss franc-pegged digital currency. It handles real money — users deposit collateral, take positions, and move significant sums between wallets. To make on-chain data easier to query, the team built a GraphQL indexer: a backend service that reads from the blockchain and presents the data through a structured API. This is a common and sensible architecture. The indexer is what introduced the problem.

## The Finding

GraphQL has a feature called introspection. It lets developers ask an API "what can you do?" and get back a complete description of every type, field, and query the server supports. This is indispensable during development — tools like <u>GraphiQL</u> and <u>Postman</u> depend on it. The problem is that most frameworks enable it by default, and many teams never turn it off when they ship to production. The result is a self-documenting attack surface: an attacker doesn't need to guess what data exists or how to query it. The API tells them.

Here, introspection returned 138 data types with no authentication required. That schema immediately identified the interesting targets: `ERC20BalanceMapping` (wallet balances), `SavingsAccount` (savings positions with exact amounts), and `TransferReference` (user-entered payment notes). From there, exploitation was mechanical. A single query returned the top savings accounts sorted by balance, largest first. Another query paged through all 7,065 wallet holders. A third returned 1,185 transfer records with their plaintext `reference` fields intact.

```bash
# Step 1: Confirm introspection is on — no credentials needed
curl -s -X POST https://[redacted-indexer-endpoint]/ \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}'

# Response: {"data":{"__schema":{"queryType":{"name":"Query"}}}}

# Step 2: Pull top savings accounts by balance, highest first
curl -s -X POST https://[redacted-indexer-endpoint]/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ savingsAccounts(orderBy: \"balance\", orderDirection: \"desc\", limit: 10) { items { id balance account } } }"
  }'
```

The response came back instantly with wallet addresses and exact balances. No rate limiting was observed at any point during testing.

## The Impact

The most immediate risk is targeting. On-chain data is technically public, but extracting a ranked list of the largest holders from raw blockchain data takes work — you need to know what contract to read, how to decode the storage layout, and how to paginate across thousands of addresses. This API compressed that effort into one HTTP request. Wallets holding seven-figure balances are now trivially identifiable, making their owners prime candidates for phishing, SIM-swap attacks, and social engineering. Crypto users with large holdings are already high-value targets; this removed the last friction that protected them.

The transfer reference exposure is a separate and arguably worse problem. Users entered notes like `"12 months loan"` and `"salary Q1 2025"` expecting them to be visible to their counterparty, not broadcast to the public internet. That data reveals business relationships, employment arrangements, and financial obligations. In the wrong hands it is blackmail material, competitive intelligence, or the basis for a very convincing spear-phishing message. If an attacker had found this before we did, they would have had a live, continuously updated feed of every significant financial relationship on the platform — and the users would never have known.

## The Fix

The immediate fix is one line of configuration. Every major GraphQL server supports disabling introspection in production environments, and it should be the default for any team shipping to users:

```javascript
// VULNERABLE — introspection always on
const server = new ApolloServer({
  schema,
});

// FIXED — introspection only in development
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
});
```

For Ponder-based indexers specifically, the same principle applies: restrict `__schema` and `__type` queries at the server configuration level before deployment. That stops the schema leak, but it does not fix unauthenticated access to the underlying data. Sensitive fields like `balance` and `reference` should require a wallet signature or API key to access — even on a blockchain-adjacent platform where some data is technically on-chain. The aggregation and indexing layer creates a new attack surface that deserves its own access controls. For transfer references specifically, if privacy is an expectation, the architecture needs to change: store a hash on-chain and provide an authenticated endpoint where parties retrieve their own references by proving wallet ownership.

## The Pattern

This finding is not a coding mistake — it is a defaults problem. GraphQL introspection ships enabled. Ponder and similar indexers are designed for developer convenience. Nobody on the team did anything wrong; they used the tools as intended and moved fast. What they missed was the moment the service crossed from "internal development tool" to "production endpoint facing the internet." That transition is where security defaults need to be explicitly revisited. Right now, before you close this tab: check every GraphQL endpoint your team runs in production and confirm introspection is disabled. If you are using Apollo Server, search your codebase for `new ApolloServer` and verify the `introspection` flag is set. If you are running a Ponder indexer, verify it is not publicly reachable without authentication.

---

If you want to know whether your app has this before an attacker does, we'll scan one endpoint for free — no strings.

---

**Technical Appendix**
CVSS Score: 5.3 | CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-16 (Configuration), CWE-284 (Improper Access Control)
