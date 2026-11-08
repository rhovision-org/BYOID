# BYOID DID Method (Draft)

## Status

Early draft. Target substrate is **rholo**.

## Goals

- Self-sovereign decentralized identifiers
- Resolution and DID document management via rholo processes
- Support for key rotation, service endpoints, and selective disclosure
- Interoperability with W3C DID Core

## Proposed Method Name

`did:byoid` or extension/alignment with `did:life` (existing RChain-related method).

## Key Properties

- Anchored to rholo unforgeable names / content-addressed registry
- Capability-based access control
- Concurrent updates via Rholang processes

## Open Questions

- Exact method name and registration
- Relationship to existing RChain DID work
- Lightweight vs full on-chain resolution
- Wallet / user-agent integration points

## References

- [rholo](https://github.com/rhovision-org/rholo)
- W3C DID Core
- Original BYOID design document
