# BYOID Architecture

## Overview

BYOID software enables self-sovereign interoperable identity. Users control their identities and personas rather than relying on third-party identity providers.

## Core Components

1. **rholo-based DID Method**
   - Substrate: [rholo](https://github.com/rhovision-org/rholo) (Rust RChain / Rholang)
   - Leverage unforgeable names, capability-based security, and concurrent processes
   - Possible relation to existing `did:life` method

2. **Self-Sovereign User Agent**
   - Aggregates personas
   - Manages credentials and selective disclosure
   - User-controlled interface to identity resources

3. **Standards Integrations**
   - OpenID Connect
   - OAuth 2.0
   - UMA (User-Managed Access)
   - W3C DIDs / Verifiable Credentials

## Next Steps

- Specify the DID method
- Prototype rholo processes for DID document storage and resolution
- Design user-agent API

See the original design document: [BYOID Cooperatives current state](https://docs.google.com/document/d/1S2ZCBFH_r8Qb8c2GNM6NsI9-JZZYhjDzwWTAKssFNCc/edit)
