# Directory structure

```
BYOID/
├── README.md
├── .env.example          # optional live OAuth / rholo settings
├── .github/workflows/    # GitHub Pages static demo deployment
├── docs/
│   ├── architecture.md
│   ├── did-method.md
│   ├── oauth.md          # Google/GitHub/Facebook/Apple live setup
│   ├── rev-proofs.md     # REV proof card format and lookup
│   └── deploy-rhobot.md  # production server, TLS, secret handling
├── public/               # browser wallet, verifier, shared DID model
│   ├── index.html
│   ├── app.js
│   ├── shared.js
│   ├── provider-catalog.js
│   ├── nodes.js          # r-wallet-style rnode list / custom node storage
│   ├── rev-proof.js      # REV proof-card signing and verification
│   ├── static-mode.js    # browser backend: live rholo writes for Pages
│   ├── rholo-web.js      # deploy signing / tuple-space client for browsers
│   ├── vendor/           # bundled MIT crypto (noble curves/hashes, bs58)
│   └── styles.css
├── src/                  # Node server, rholo client, OAuth adapters
├── test/                 # node:test unit tests
├── scripts/              # OAuth readiness, deploy, and registry tools
├── deploy/               # systemd / nginx / production env assets
├── contracts/            # Rholang proof registry + deployment metadata
└── examples/             # usage examples and demos
```
