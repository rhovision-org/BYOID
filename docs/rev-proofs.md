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
- Rholang index: the contract in
  [`contracts/rev-proof-registry.rho`](../contracts/rev-proof-registry.rho)
  (version 2) stores the latest card string per address for Rholang
  consumers. It is registered with `rho:registry:insertArbitrary`, and each
  network's URI is recorded in
  [`public/rev-registry-uris.js`](../public/rev-registry-uris.js).

The registry resolves to two facets. Program builders are in
[`public/rev-registry.js`](../public/rev-registry.js).

```rholang
// In a deploy signed by the REV key that owns <address>:
@publishFacet!(*deployerId, ["<address>", "<card>"], *ret)
// In any deploy:
@readFacet!(["<address>"], *ret)
```

- **Only the owner publishes.** The contract derives the caller's REV address
  from `rho:rchain:deployerId` with `rho:rev:address` and refuses any other
  address. A forged deployer id derives `Nil`, which matches nothing.
- **No public listener.** Version 1 listened on `@"byoid:rev:registry"`, where
  anyone could add a second listener and take calls. Version 2 is reached only
  through its URI.
- **Private answers.** Replies go to a `ret` the caller creates with `new`:
  `{"ok": true}`, `{"ok": true, "card": …}` or `{"ok": false, "error": …}`.
  The programs forward the answer to `rho:rchain:deployId`.
- **Fail closed.** Non-string arguments, an address outside 45–60 characters,
  or a card over 19,000 characters are refused before state is touched.

The static app (GitHub Pages) signs the publish deploy with the REV key in the
browser, funded by the network's faucet, and writes the direct name in the same
deploy. The hosted server deploys with its own key, so it writes the direct
name only. Without a registry URI for the network, the app writes the direct
name only.

The v1 contract is still listening on `@"byoid:rev:registry"` on the
playground. Nothing in BYOID calls it any more; its entries are not migrated,
because each card is re-indexed the next time its owner publishes.

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

The script probes the recorded URI first and skips installation when the
registry already answers. After an install it writes the new URI to
`public/rev-registry-uris.js`; commit that file so the app uses it. If a network accepts the deploy into its pool but does not propose it,
the script records the registry as unavailable and the app falls back to direct
card names, which do not require a contract call.

## Privacy and threat model

Publishing a card deliberately reveals the provider handles you include. The
agent attestations contain only hashes; the card adds the handle so a verifier
can hash it and compare. Do not publish a card unless you want those handles
publicly associated with the REV address and DID.
