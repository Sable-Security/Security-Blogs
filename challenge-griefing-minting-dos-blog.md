# The Free Infinite Loop That Could Freeze Any Minting Position

The attack costs gas. That is the entire price of entry — no tokens at risk, no collateral lost, no capital locked. Just transaction fees, running in a loop, forever. We found a sequence of two smart contract calls on a DeFi minting protocol that allows any attacker to permanently prevent any position owner from minting their stablecoin, withdrawing their collateral, or adjusting their price. The position stays open, the owner's funds stay locked inside it, and the attacker pays a few dollars per block to keep it that way.

## What We Were Looking At

The target is a DeFi protocol that lets users mint a Swiss franc-pegged stablecoin by depositing collateral. Users open "positions" — essentially on-chain vaults — deposit assets, and draw out stablecoin against that collateral. To keep the system solvent, the protocol includes a challenge mechanism: anyone can challenge a position they believe is undercollateralized, locking it temporarily while the market resolves whether the challenge is legitimate. This challenge-and-liquidation system is the core safety mechanism. It is also where we found the problem.

## The Finding

When a challenger initiates a challenge, the target position enters a locked state. The `noChallenge` modifier blocks minting, collateral withdrawal, and price adjustment until the challenge resolves. This is by design — an active challenge means the position's health is in question.

The protocol also allows challengers to cancel their own challenge before it matures. When a challenger self-cancels, the contract skips the payment that a third-party buyer would have to make, hands the challenger their collateral stake back in full, and clears the challenge. The position then enters a one-day minting cooldown — but critically, it can be re-challenged immediately.

```solidity
// From MintingHub._avertChallenge():
if (msg.sender == _challenge.challenger) {
    // No payment required — challenger cancels for free
} else {
    zchf.transferFrom(msg.sender, _challenge.challenger, (size * liqPrice) / (10 ** 18));
}
_challenge.position.notifyChallengeAverted(size); // triggers 1-day mint cooldown
_challenge.position.collateral().transfer(msg.sender, size); // full collateral returned
```

And nothing stops the same challenger from immediately starting a new challenge on the same position:

```solidity
// From Position.notifyChallengeStarted():
function notifyChallengeStarted(uint256 size) external onlyHub alive {
    if (size < minimumCollateral && size < _collateralBalance()) revert ChallengeTooSmall();
    challengedAmount += size; // no cooldown check here
}
```

The loop is: challenge → wait one block → self-cancel for free → challenge again. On each iteration the challenger recovers their full collateral stake. The only expenditure is gas. The position stays locked across the entire loop because `challengedAmount` is always greater than zero by the time the next challenge begins.

The protocol had previously patched a related finding that allowed the same attack within a single block, adding `require(block.timestamp != _challenge.start)`. That stops the same-block version. The multi-block version — challenge in block N, cancel in block N+1 — is untouched.

## The Impact

The position owner cannot mint, cannot withdraw collateral, and cannot adjust their price as long as the attack runs. Their collateral sits inside a contract they can no longer manage. Positions are time-limited on this protocol — they have an expiration date — so an attacker who runs this loop for long enough destroys the entire economic value of the position without ever stealing a single token. The owner paid upfront fees for minting capacity they will never access.

The consequences extend beyond the individual target. This protocol allows position owners to create clones — child positions that inherit minting capacity from a parent. A single griefed parent blocks minting across all of its associated clones simultaneously, because clone capacity is bounded by what the original can still support. A well-chosen target multiplies the damage. For a sophisticated actor — a short-seller, a competitor, a liquidation bot trying to move markets — the cost-to-impact ratio is extraordinary: ongoing gas fees against the frozen TVL of a seven-figure position.

## The Fix

There are several viable paths forward, and the right one depends on how the protocol wants to balance challenger flexibility against griefing resistance.

The most robust fix is to require challengers who self-cancel to forfeit a fraction of their collateral stake as a penalty. A 2% haircut on the minimum collateral requirement, per loop iteration, quickly makes sustained griefing expensive while barely affecting a legitimate challenger who made a reasonable bet and changed their mind:

```solidity
// VULNERABLE — free self-cancellation, full collateral returned
if (msg.sender == _challenge.challenger) {
    _challenge.position.collateral().transfer(msg.sender, size);
}

// FIXED — penalty forfeited to protocol reserve on self-cancel
if (msg.sender == _challenge.challenger) {
    uint256 penalty = (size * CANCEL_PENALTY_BPS) / 10_000; // e.g. 200 = 2%
    _challenge.position.collateral().transfer(msg.sender, size - penalty);
    // penalty routes to protocol reserve or is burned
}
```

An alternative that does not touch the economics: require challengers to wait for a minimum fraction of the challenge period before self-cancellation is permitted. If the challenge period is 24 hours and self-cancellation is blocked until hour 6, the attacker's collateral is locked for six hours per loop iteration instead of one block. Sustained griefing goes from a few dollars in gas to a meaningful capital commitment:

```solidity
// Self-cancellation gated on minimum commitment time
if (msg.sender == _challenge.challenger) {
    require(
        block.timestamp >= _challenge.start + challengePeriod / 4,
        "Challenge too recent to cancel"
    );
}
```

Either fix changes the attacker's calculus from "gas only" to "gas plus real capital cost" — the threshold that makes this attack economically irrational.

## The Pattern

This finding is a category of vulnerability that recurs in DeFi protocol design: an asymmetric action pair where one direction has friction and the other does not. The challenge system was designed to make starting a challenge meaningful — you post collateral, you commit to a process. But the cancel path was left as a pure convenience feature with no corresponding weight. Whenever a protocol creates a mechanism that locks someone else's funds, the exit path for the initiating party needs to carry at least some proportionate cost. Right now, before you close this tab: if your protocol has a challenge, dispute, or locking mechanism, check whether the initiating party can reverse their action at zero economic cost. If they can, map the loop. If that loop keeps the target locked while the initiator recovers their stake, you have this vulnerability.

---

If you want to know whether your protocol has this before an attacker does, we'll scan one endpoint for free — no strings.

---

**Technical Appendix**
CVSS Score: 5.3 | CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
CWE-400 (Uncontrolled Resource Consumption), CWE-799 (Improper Control of Interaction Frequency), CWE-834 (Excessive Iteration)
