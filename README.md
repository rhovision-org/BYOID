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

## Getting Started

This repository is in early stages. Initial scaffolding and design documents will be added here.

Contributions, issues, and discussions are welcome.

## License

To be determined (likely a permissive open-source license such as Apache 2.0 or MIT).

---

*This project continues the long-running BYOID collaboration involving participants from RChain, Holochain, DivvyDAO, FreeTrust, and other communities focused on trustworthy, user-controlled identity.*
