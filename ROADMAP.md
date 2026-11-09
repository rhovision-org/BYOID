# BYOID Roadmap

The proof of concept already creates `did:byoid` identities in the browser,
anchors a signed event log on rholo, links OAuth accounts, issues credentials
with selective disclosure, and publishes REV proof cards. This roadmap covers
what comes next. Each item is a GitHub issue grouped under a milestone.

The goals carry forward from the FreeTrust and BYOID design work: own your
identity, prove only what you choose, recover it through people you trust, and
check the important parts formally.

## M1 Identity core

Make an identity something a person can keep for years.

- [#1](https://github.com/rhovision-org/BYOID/issues/1) Write the did:byoid method specification
- [#2](https://github.com/rhovision-org/BYOID/issues/2) Add key rotation to the DID event log
- [#3](https://github.com/rhovision-org/BYOID/issues/3) Account recovery with trusted guardians (needs #2)
- [#4](https://github.com/rhovision-org/BYOID/issues/4) Support off-chain DIDs alongside did:byoid
- [#5](https://github.com/rhovision-org/BYOID/issues/5) Choose and add a license

## M2 Standard credentials

Make credentials readable by other wallets and verifiers.

- [#6](https://github.com/rhovision-org/BYOID/issues/6) Align credentials with W3C VC 2.0 and SD-JWT VC
- [#7](https://github.com/rhovision-org/BYOID/issues/7) In-person QR presentation: prove over 21 without revealing identity (needs #6)
- [#8](https://github.com/rhovision-org/BYOID/issues/8) OpenID4VP and OpenID Connect integration (needs #6)

## M3 Trust and risk

Build trust between people and measure how much a claim can be relied on.

- [#9](https://github.com/rhovision-org/BYOID/issues/9) Web-of-trust peer attestations
- [#10](https://github.com/rhovision-org/BYOID/issues/10) Passkeys and user-chosen authentication factors
- [#11](https://github.com/rhovision-org/BYOID/issues/11) MrE risk scoring prototype (needs #9, #10)
- [#12](https://github.com/rhovision-org/BYOID/issues/12) Capability-based authorization for shared data

## M4 Assurance and usability

Show that it is safe and that ordinary people can use it.

- [#13](https://github.com/rhovision-org/BYOID/issues/13) Formal model of the DID event log and recovery protocol (needs #2, #3)
- [#14](https://github.com/rhovision-org/BYOID/issues/14) Verify the REV proof registry contract
- [#15](https://github.com/rhovision-org/BYOID/issues/15) Privacy review of public anchors
- [#16](https://github.com/rhovision-org/BYOID/issues/16) Usability testing with first users

Milestones are ordered by dependency, not by date. Work in M3 and M4 can start
early where it does not depend on M1.
