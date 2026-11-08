# Directory structure

```
BYOID/
├── README.md
├── .env.example          # optional live OAuth / rholo settings
├── .github/workflows/    # GitHub Pages static demo deployment
├── docs/
│   ├── architecture.md
│   └── did-method.md
├── public/               # browser wallet, verifier, shared DID model
│   ├── index.html
│   ├── app.js
│   ├── shared.js
│   ├── provider-catalog.js
│   ├── static-mode.js    # browser-only backend for GitHub Pages
│   └── styles.css
├── src/                  # Node server, rholo client, OAuth adapters
├── test/                 # node:test unit tests
├── examples/             # usage examples and demos
└── contracts/            # rholang / rholo processes (future)
```
