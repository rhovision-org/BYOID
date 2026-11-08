# BYOID

**Bring Your Own Identity** — software for interoperable self-sovereign identity.

This repository is for the development of open-source software realizing the BYOID vision: users own and control their identities and personas across systems, with strong privacy, interoperability, and user agency.

## Vision

Users should be able to:
- Prove identity once and reuse it across services
- Aggregate multiple personas under a single self-sovereign identity
- Control exposure of personal information (reducing provider liability)
- Build trustworthy pseudo-anonymous identities and reputation in webs of trust
- Use standards-compliant mechanisms (DIDs, OpenID Connect, OAuth 2.0, UMA, etc.)

The original living design document is available here:  
[BYOID Cooperatives current state (Google Doc)](https://docs.google.com/document/d/1S2ZCBFH_r8Qb8c2GNM6NsI9-JZZYhjDzwWTAKssFNCc/edit)

## Technical Direction

- **DIDs on rholo**: Use [rholo](https://github.com/rhovision-org/rholo) (the Rust implementation of RChain / Rholang) as the substrate for decentralized identifiers. Rholo provides concurrent process execution, unforgeable names, capability-based security, and a content-addressed registry well-suited to self-sovereign identity.
- Self-sovereign user agent components that give users (and groups) control over their identity resources rather than relying on third-party interfaces.
- Interoperability with existing identity platforms and standards while prioritizing open-source partner projects.
- Privacy by default, with selective disclosure and user-managed authorization.

Historical related work includes the earlier [DigitalLifeCollective/byoid](https://github.com/DigitalLifeCollective/byoid) repository (which contained a DID-OAuth2 server component).

## Project Goals

1. Define and implement a rholo-based DID method (or extension of an existing RChain-related method such as `did:life`).
2. Build user-agent tooling for identity aggregation, credential management, and selective disclosure.
3. Provide reference integrations (OpenID Connect provider/relying party, OAuth2, etc.) that respect user control.
4. Document the architecture and make the system easy for ordinary users and communities to adopt.

## Live demo

**[jimscarver.com/BYOID](https://jimscarver.com/BYOID/)**  
(GitHub Pages project site; `jimscarver.github.io/BYOID` redirects here.)

The GitHub Pages build runs without a Node server but uses the real rholo
playground. The browser generates a local devnet phlo key, requests test REV
from the playground faucet, signs and submits its own deploys, and reads the
DID event log back from the public tuple-space name. DID keys, credentials and
selective disclosure remain browser-local. OAuth provider sign-in is simulated
in demo mode because client secrets cannot live in a static site.

## Run the full POC locally

The Node app performs live anchor reads and writes against the rholo playground.

```bash
npm install
npm start          # http://127.0.0.1:3000
npm test           # 22 unit tests
```

No credentials are required. Google, GitHub and Facebook run in demo mode until
you set their OAuth client id/secret pairs in `.env` (see `.env.example`).

### What the POC demonstrates

1. A P-256 keypair and `did:byoid` identifier generated in the browser; the
   private key never leaves IndexedDB.
2. A signed, hash-linked DID event log anchored at a public rholo name.
3. Demo or live OAuth linking, with the link agent signing hash-only
   attestations.
4. Credentials signed in the browser with selective disclosure of handle,
   email, verification status and date.
5. A verifier that resolves the issuer DID, checks the event chain, attestations,
   disclosed-field hashes and revocations using the same shared code as the
   server.
6. A **New identity** action that removes the current browser wallet and anchors
   a fresh DID, reusing the same local devnet phlo key.
7. An r-wallet-style **rnode picker**: Rholang Playground, Rhobot Testnet,
   History, localhost-0 … localhost-4, and custom nodes stored in the browser.
   The GitHub Pages build talks to the selected node directly; the Node server
   uses `RHOLO_URL`.

Design notes: [architecture](docs/architecture.md) ·
[DID method draft](docs/did-method.md).

## Getting Started

The repository now contains the POC above plus the original design documents.
Contributions, issues, and discussions are welcome.

## License

To be determined (likely a permissive open-source license such as Apache 2.0 or MIT).

---

*This project continues the long-running BYOID collaboration involving participants from RChain, Holochain, DivvyDAO, FreeTrust, and other communities focused on trustworthy, user-controlled identity.*
