# REV proof cards

BYOID's REV proof lookup is a Keybase-style proof directory keyed by a REV
address. It lets someone answer: **"which provider proofs are bound to this REV
address?"** without trusting the name they read from.

## Card format

A proof card is public JSON with these fields in the signed body:

```json
{
  "v": 1,
  "type": "byoid.rev.proofs",
  "revAddress": "1111…",
  "revPublicKey": "04…",
  "did": "did:byoid:…",
  "network": "playground",
  "shardId": "/playground",
  "issuedAt": "2026-11-08T…",
  "agentFingerprint": "sha256:…",
  "proofs": [
    {
      "provider": "github",
      "handle": "octocat",
      "subjectHash": "…",
      "attestation": "<compact ES256 JWS>",
      "attestationHash": "…",
      "linkEventId": "…",
      "linkedAt": "…",
      "demo": false
    }
  ],
  "didSignature": "<base64url P-256 signature>",
  "revSignature": "<base64url DER secp256k1 signature>"
}
```

Both signatures cover `canonicalize(body)` where `body` is every field above
except `didSignature` and `revSignature`.

- `revSignature` uses BLAKE2b-256 over the canonical bytes, matching rholo's
  secp256k1 signing convention.
- `didSignature` is ES256 over the same canonical bytes.
- The reader derives the REV address from `revPublicKey` and compares it to the
  requested address.
- The reader resolves `did` on the selected rnode and verifies that every
  provider proof matches an anchored link event.
- The agent attestation is verified against the current BYOID agent key, and
  the handle is checked against the attestation's `handleHash`.

## On-chain names

- Direct card name: `byoid:rev:<revAddress>`. The app writes the base64url JSON
  card here and reads all cards from this name. A public name is a bulletin
  board; readers verify signatures and ignore invalid values.
- Rholang index: `byoid:rev:registry`. The contract in
  [`contracts/rev-proof-registry.rho`](../contracts/rev-proof-registry.rho)
  stores the latest card string per address for Rholang consumers. Publishing
  writes the contract index and the direct name in one deploy.

Contract calls:

```rholang
@"byoid:rev:registry"!("publish", "<address>", "<card>", "<resultName>")
@"byoid:rev:registry"!("get", "<address>", "unused", "<resultName>")
```

`resultName` is a public name chosen by the caller, so concurrent reads do not
need a shared response channel. The contract peeks at its state for `get` and
replaces the state map for `publish`.

## Deploying the registry

```bash
# Playground / testnet
node scripts/deploy-rev-registry.js https://playground.rhobot.net
node scripts/deploy-rev-registry.js https://testnet.rhobot.net
```

Deployment metadata is recorded in
[`contracts/deployments.json`](../contracts/deployments.json). History is a
read-only snapshot, so the contract cannot be deployed there; the direct
`byoid:rev:<address>` cards are still readable if they were written on that
chain.

The script probes the contract first and skips deployment when it already
answers. If a network accepts the deploy into its pool but does not propose it,
the script records the registry as unavailable and the app falls back to direct
card names, which do not require a contract call.

## Privacy and threat model

Publishing a card deliberately reveals the provider handles you include. The
agent attestations contain only hashes; the card adds the handle so a verifier
can hash it and compare. Do not publish a card unless you want those handles
publicly associated with the REV address and DID.
