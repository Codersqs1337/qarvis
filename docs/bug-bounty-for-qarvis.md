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
