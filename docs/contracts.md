# Rholang contract plan

**Status:** design proposal, not implemented. The only deployed contract today
is [`contracts/rev-proof-registry.rho`](../contracts/rev-proof-registry.rho).
DID event logs are written to public names and verified entirely by clients.

This plan names the contracts BYOID needs, the rules they share, and the
extension point that lets FreeTrust modules plug in without changing the core.

## Design rules

These apply to every BYOID contract.

1. **Contracts are indexes and gatekeepers, not trust anchors.** Readers
   still verify every signature and hash link themselves, as
   `public/shared.js` does today. A contract only makes it harder to
   disrupt or confuse the index.
2. **Writers are authenticated by `deployerId`.** A contract takes the
   caller's `*deployerId` and asks `rho:rchain:deployerId:ops` for
   `"pubKeyBytes"`. Any other name gets `Nil` and is refused. Caller-supplied
   names prove nothing, since anyone can mint fresh ones with `new`. This
   follows the QLF knowledge base design
   ([QLF PR #216](https://github.com/rhovision-org/quantum-logical-framework/pull/216), §3a).
3. **Contracts are found by registry URI, not public string names.** Anyone
   can deploy a second listener on `@"byoid:rev:registry"` and consume its
   calls. Registering with `rho:registry:insertSigned:secp256k1` gives a URI
   only the BYOID release key can claim. Clients look it up with
   `rho:registry:lookup`.
4. **Replies go to a channel the caller creates.** Every method takes a
   `return` name from `new`, so results cannot be read or spoofed by others.
5. **State grows where possible.** Attestations, approvals, revocations and
   nullifiers are sets that only gain members, so shards can accept writes
   in any order without a cross-shard transaction. Withdrawal is a second
   signed set, not a delete.
6. **Inputs fail closed, with an answer.** Malformed input gets
   `{ok: false, error: …}` before it reaches state or a system process.
7. **Every method has the same envelope:**
   `(method, version, deployerId, args, return)`. A new version adds
   methods; old clients keep working.

## The key-type gap

DID keys are P-256 (WebCrypto). rholo's system processes verify
`secp256k1` and `ed25519` signatures, not P-256. So a contract cannot check
a DID event signature on chain today. Two ways forward, for the method spec
(#1):

- **Bind a deployer key to the DID.** The `create` event names a secp256k1
  controller key, and the contract accepts later writes only from that
  deployer. The browser already makes a secp256k1 REV key for proof cards.
- **Add a P-256 verify system process to rholo.** This is cleaner but needs a
  rholo change, filed as an issue there.

The plan below assumes the first option.

## Core contracts

| Contract | Purpose | State | Roadmap |
| --- | --- | --- | --- |
| DID registry | Append-only event log per DID. Refuses forks (wrong `seq` or `prev`) and writes from anyone but the bound controller key | `did → [event]`, `did → controllerKey` | #1, #2 |
| Recovery | Guardian set, threshold and delay per DID. Guardians approve with their own `deployerId`. After the delay, a threshold of approvals installs a new controller key unless the current key cancels | `did → {guardians, threshold, delayBlocks, pending}` | #3 |
| Attestations | Signed claims by one DID about another. Records the attester key, counts distinct keys, keeps a withdrawal set | `subject → {attestation id → {body, attesterKeys}}` | #9, #18 |
| Status list | Credential revocation by issuer, grow-only | `issuer → Set(credentialId)` | #6 |
| REV proof registry | Existing contract, hardened: only the key that owns a REV address may publish its card | `revAddress → card` | #14 |

Delays use block height from `rho:block:data`. Hashes use
`rho:crypto:blake2b256Hash`. REV addresses come from `rho:rev:address`.

## FreeTrust extension point

FreeTrust adds features on top of identity: personal rules, risk scoring,
anonymous voting, notary and trust tokens. They should plug in, not fork the
core. Two mechanisms cover this.

**Policy hooks (personal rules).** A DID may register one policy contract
URI. Before the core accepts a write on that DID's behalf (a rotation, a new
capability grant, a disclosure), it sends the request to the policy contract
and proceeds only on `{allow: true}`. A policy is ordinary Rholang the user
chooses or writes, so "require two factors for rotation" or "never disclose
my email to unverified parties" become code the user owns. With no policy
registered, the default rules apply.

**Extension registry.** A contract that maps a module name to its registry
URI and interface version, written by the BYOID release key. Core contracts
publish events (DID created, attestation added, credential revoked) to
modules that subscribe. Modules never write core state directly.

| FreeTrust module | What it adds | Builds on |
| --- | --- | --- |
| Social contracts and personal rules | User policy contracts as above | Policy hooks |
| MrE risk oracle | Signed risk scores posted by an off-chain scorer, keyed by presentation or DID | Attestations, #11 |
| Anonymous one person, one vote | Grow-only nullifier set per poll, so each person votes once without revealing who | Proof of personhood, #18 |
| Capabilities and UMA | Revocable forwarders (caretaker pattern) around unforgeable names; rholo's `ocapn` crate may help | #12 |
| Notary | Hash anchoring with timestamps | `rho:crypto:blake2b256Hash`, `rho:block:data` |
| Trust tokens | Pledges and thank-you credits, possibly via `rho:rchain:ertp:ledger` | Attestations |
| rhogov link | Use `rho:gov:trustLevels` as one input to attestation weight | #18 |

## Order of work

1. Harden the REV proof registry (#14), since it is deployed and the fix is
   small. It proves the `deployerId`, registry URI and return channel
   patterns.
2. DID registry with a bound controller key (#1, #2).
3. Attestations and status list (#9, #6).
4. Recovery (#3), then the policy hook.
5. Extension registry and the first FreeTrust module (the notary is the
   smallest).

Each contract gets acceptance tests on an isolated rholo node before it is
deployed to the playground or testnet, and its properties go into the formal
model (#13).
