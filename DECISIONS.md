# Decisions

Choices that shape BYOID, newest first. Decisions that span several
rhovision-org repos are recorded in
[FreeTrust DECISIONS.md](https://github.com/rhovision-org/FreeTrust/blob/master/DECISIONS.md); this file
records BYOID's own.

| Date | Decision | Why | Where |
| --- | --- | --- | --- |
| 2026-11-09 | Use the shared MrE work for risk scoring instead of building a scorer here | Rooms, governance and identity need the same update, and nodes must agree exactly | [#11](https://github.com/rhovision-org/BYOID/issues/11), [QLF#221](https://github.com/rhovision-org/quantum-logical-framework/issues/221) |
| 2026-11-09 | Contracts authenticate callers by `deployerId`, are found by registry URI, reply on caller-created channels, and keep state grow-only where possible | Public string names can be overwritten or intercepted, and caller-supplied names prove nothing | [docs/contracts.md](docs/contracts.md) |
| 2026-11-09 | Bind a secp256k1 controller key to each DID until rholo can verify P-256 | DID keys are P-256, and rholo verifies only secp256k1 and ed25519 | [#1](https://github.com/rhovision-org/BYOID/issues/1), [rholo#560](https://github.com/rhovision-org/rholo/issues/560) |
| 2026-11-09 | Milestones are ordered by dependency, not by date | Work in later milestones can start early where it doesn't depend on earlier ones | [ROADMAP.md](ROADMAP.md) |
| 2026-11-06 | Support both on-chain (`did:byoid`) and off-chain DIDs | People can start without a chain write and anchor later | [#4](https://github.com/rhovision-org/BYOID/issues/4) |
| Before 2026-11 | DID keys are P-256, generated in the browser and kept in IndexedDB | WebCrypto supports P-256, and the private key never leaves the browser | [README](README.md) |
| Before 2026-11 | The DID event log lives at a public rholo name, and every reader verifies signatures and hash links | A public name is a bulletin board; trust comes from the signed chain, not write access | [src/anchor.js](src/anchor.js), [docs/did-method.md](docs/did-method.md) |
| Before 2026-11 | OAuth link attestations carry only hashes | Linking an account should not publish the handle or email | [README](README.md), [docs/rev-proofs.md](docs/rev-proofs.md) |
