# Live OAuth setup

BYOID supports live Google, GitHub, Facebook, and Apple sign-in through the Node
server. The GitHub Pages build cannot run this flow securely because it cannot
keep a client secret or sign server-side attestations. The Pages build remains
in demo mode by design.

## Common settings

```bash
PUBLIC_URL=https://your-byoid-host.example
```

`PUBLIC_URL` determines every callback URL below. The provider console must
contain the exact callback string; changing `PUBLIC_URL` requires updating all
four provider apps.

## Google

1. Create an OAuth 2.0 Client ID of type **Web application** in Google Cloud.
2. Add the authorized redirect URI:
   `https://your-byoid-host.example/auth/google/callback`
3. Set:
   ```
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...
   ```

Scopes: `openid email profile`.

## GitHub

1. Create an OAuth App under the account or organization that will own it.
2. Set the authorization callback URL:
   `https://your-byoid-host.example/auth/github/callback`
3. Set:
   ```
   GITHUB_CLIENT_ID=...
   GITHUB_CLIENT_SECRET=...
   ```

Scopes: `read:user user:email`. BYOID reads the primary verified email when the
account grants it.

## Facebook

1. Create a Meta app with the **Facebook Login** product.
2. Add the valid OAuth redirect URI:
   `https://your-byoid-host.example/auth/facebook/callback`
3. Set:
   ```
   FACEBOOK_CLIENT_ID=...
   FACEBOOK_CLIENT_SECRET=...
   ```

Use HTTPS for a production Facebook app. The Graph API does not assert email
verification, so BYOID marks Facebook email as unverified.

## Apple

Apple uses a **Services ID**, a Team ID, a Key ID, and a `.p8` private key. BYOID
generates the short-lived Apple client-secret JWT from those values. You may
also supply a pre-generated `APPLE_CLIENT_SECRET` JWT instead.

1. In Apple Developer, create a Services ID and enable **Sign in with Apple**.
2. Configure the domain and return URL:
   `https://your-byoid-host.example/auth/apple/callback`
3. Create a Sign in with Apple key and download the `.p8` file.
4. Set:
   ```
   APPLE_CLIENT_ID=com.example.byoid.web
   APPLE_TEAM_ID=...
   APPLE_KEY_ID=...
   APPLE_PRIVATE_KEY_PATH=./AuthKey_XXXXXXXXXX.p8
   # or: APPLE_CLIENT_SECRET=<pre-generated JWT>
   ```

BYOID requests the `name email` scopes, verifies the Apple identity token
against Apple's JWKS, checks issuer, audience, expiry, and nonce, and reads the
stable `sub` claim. Apple returns the person's name only on first authorization;
the normalized handle falls back to the email prefix when no name is available.

## Check configuration

```bash
npm run oauth:check
```

This prints each provider's mode, callback URI, and the environment variables
still missing. It never prints secrets.

## Security notes

- Never put client secrets or the Apple `.p8` key in this repository or in the
  GitHub Pages build.
- The server exchanges authorization codes and signs the BYOID link
  attestation. The browser receives only the normalized profile and the
  attestation; provider tokens stay on the server.
- The BYOID agent key is separate from the rholo deploy key. Neither key can
  sign as the user's DID.
- Apple requires a publicly reachable HTTPS callback for production. Use a
  tunnel (for example Cloudflare Tunnel or ngrok) when testing locally.
