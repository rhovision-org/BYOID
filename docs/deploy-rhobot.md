# Deploying the live BYOID OAuth server on rhobot-2

The GitHub Pages build remains a browser-only demo: it cannot hold OAuth client
secrets or sign server-side agent attestations. The **live OAuth app** runs on
`rhobot-2` and is served at:

**https://byoid.rhobot.net**

Use that origin for live Google, GitHub, Facebook and Apple sign-in. The Pages
build is still useful as a zero-install demo and chain explorer.

## Topology

```
browser
  │  HTTPS
  ▼
nginx  byoid.rhobot.net :443          TLS + reverse proxy
  │
  ▼
node 127.0.0.1:3100                  BYOID server (systemd, user byoid)
  ├── public/                        the same browser app, served same-origin
  ├── /var/lib/byoid/                agent key, deploy key, persistent state
  └── /etc/byoid/byoid.env           OAuth secrets (root:root, 0600)
  │
  ▼
https://playground.rhobot.net       rholo anchoring
```

- Code lives in immutable releases under `/opt/byoid/releases/<commit>`.
- `/opt/byoid/current` points at the active release.
- The app's `data` directory is a symlink to `/var/lib/byoid`, so keys survive
  code updates.
- The server binds loopback only. Nginx is the only public listener.
- Provider client secrets exist only in `/etc/byoid/byoid.env`. They are never
  in Git, the static Pages artifact, the browser, or the process argument list.

## Register these callback URLs

Register the exact HTTPS callback URI with each provider. A provider console is
case-sensitive and scheme-sensitive; `http`, trailing slashes, or the Pages
origin will fail.

| Provider | Redirect URI |
| --- | --- |
| Google | `https://byoid.rhobot.net/auth/google/callback` |
| GitHub | `https://byoid.rhobot.net/auth/github/callback` |
| Facebook | `https://byoid.rhobot.net/auth/facebook/callback` |
| Apple | `https://byoid.rhobot.net/auth/apple/callback` |

Apple also requires the domain `byoid.rhobot.net` under the Services ID's
**Domains and Subdomains** setting. Facebook production apps require HTTPS and a
valid OAuth redirect URI. See [oauth.md](oauth.md) for each provider's app
registration steps.

## Secret handling

The only production secret file is:

```text
/etc/byoid/byoid.env     root:root 0600
```

Install it from the repository template and edit it **on the server**:

```bash
sudo install -d -m 0750 /etc/byoid
sudo install -m 0600 /opt/byoid/current/deploy/byoid.env.example /etc/byoid/byoid.env
sudo editor /etc/byoid/byoid.env
sudo chmod 0600 /etc/byoid/byoid.env
sudo systemctl restart byoid
```

Rules:

- Do **not** put credentials in `.env` inside the deployed release, in Git, in
  GitHub Actions variables, or in the Pages build.
- Do **not** paste the file, `env` output, or the systemd process environment
  into an issue, chat, or log.
- Apple `.p8` files should live at `/etc/byoid/`, owned `root:root`, mode `0600`.
  Reference it with an absolute `APPLE_PRIVATE_KEY_PATH`.
- `npm run oauth:check` reports modes and missing **variable names** only. It
  never prints values.
- The agent key and rholo deploy key are generated under `/var/lib/byoid` with
  restrictive permissions. The deploy key pays phlo; it cannot sign as a user.

Set `OAUTH_DEMO=off` once all providers you intend to use are configured. With
`auto`, configured providers use live OAuth and unconfigured providers remain
labelled demos.

## First-time host setup

Run the provisioning commands as root on `rhobot-2`
(`ssh -i ~/.ssh/id_droplet root@rhobot.net`). The release install and switch
are run from the workstation.

1. Create the service account and persistent directories:

   ```bash
   useradd --system --home-dir /var/lib/byoid --shell /usr/sbin/nologin byoid
   install -d -m 0755 /opt/byoid/releases
   install -d -m 0700 -o byoid -g byoid /var/lib/byoid
   install -d -m 0750 /etc/byoid
   ```

2. Install the systemd unit and production env template. From the repository
   checkout on the workstation:

   ```bash
   scp -i ~/.ssh/id_droplet deploy/byoid.service root@rhobot.net:/etc/systemd/system/byoid.service
   scp -i ~/.ssh/id_droplet deploy/byoid.env.example root@rhobot.net:/tmp/byoid.env
   ssh -i ~/.ssh/id_droplet root@rhobot.net '
     install -m 0600 -o root -g root /tmp/byoid.env /etc/byoid/byoid.env
     rm -f /tmp/byoid.env
     systemctl daemon-reload
   '
   ```

3. Confirm Node 22 is available at `/usr/local/lib/node22/bin/node`. The service
   intentionally uses that binary rather than the host's older default Node.

4. Add the DNS record before requesting a certificate:

   ```bash
   doapi cocloud /v2/domains/rhobot.net/records -X POST \
     -H 'Content-Type: application/json' \
     -d '{"type":"A","name":"byoid","data":"138.197.65.34","ttl":3600}'
   dig +short byoid.rhobot.net    # expected: 138.197.65.34
   ```

5. Install the first release and start the service from the workstation:

   ```bash
   ./scripts/deploy-rhobot.sh
   ```

   That script installs the committed tree into
   `/opt/byoid/releases/<sha>`, installs production dependencies, links `data`
   to `/var/lib/byoid`, switches `/opt/byoid/current`, restarts
   `byoid.service`, and waits for `/healthz`.

6. Install the temporary HTTP vhost, obtain the certificate, then replace it
   with the TLS vhost:

   ```bash
   ssh -i ~/.ssh/id_droplet root@rhobot.net '
     install -m 0644 /opt/byoid/current/deploy/nginx/byoid.rhobot.net.http.conf \
       /etc/nginx/sites-available/byoid.rhobot.net
     ln -sfn /etc/nginx/sites-available/byoid.rhobot.net \
       /etc/nginx/sites-enabled/byoid.rhobot.net
     nginx -t && systemctl reload nginx
     certbot --nginx -d byoid.rhobot.net --non-interactive --agree-tos --redirect
     install -m 0644 /opt/byoid/current/deploy/nginx/byoid.rhobot.net.conf \
       /etc/nginx/sites-available/byoid.rhobot.net
     nginx -t && systemctl reload nginx
     systemctl enable byoid nginx
   '
   ```

7. Verify:

   ```bash
   curl -fsS https://byoid.rhobot.net/healthz
   curl -fsS https://byoid.rhobot.net/api/config | jq '.providers[] | {id, mode}'
   ```

## Current production state

As deployed on 2026-11-08:

- `byoid.rhobot.net` A record points to `rhobot-2` (`138.197.65.34`).
- Let's Encrypt certificate is active; renewal is handled by certbot's timer.
- `byoid.service` is enabled and binds `127.0.0.1:3100`.
- Nginx terminates TLS and proxies to the service.
- All four providers start in demo mode until credentials are installed in
  `/etc/byoid/byoid.env`. The app itself, chain anchoring, and the OAuth
  callback machinery are live.

## Normal deploy

From the repository on the workstation:

```bash
./scripts/deploy-rhobot.sh
```

The script:

1. requires a clean working tree,
2. exports the committed tree to `/opt/byoid/releases/<sha>`,
3. installs production dependencies with Node 22,
4. points `data` at `/var/lib/byoid`,
5. atomically switches `/opt/byoid/current`,
6. restarts `byoid.service` and waits for `/healthz`.

It keeps the active release plus four previous releases.

## Update credentials

Edit the file on the server, then restart only the app:

```bash
sudo editor /etc/byoid/byoid.env
sudo chmod 0600 /etc/byoid/byoid.env
sudo systemctl restart byoid
sudo journalctl -u byoid -n 30 --no-pager
```

To check without exposing values:

```bash
sudo systemd-run --quiet --pipe --wait --collect \
  --property=EnvironmentFile=/etc/byoid/byoid.env \
  --property=WorkingDirectory=/opt/byoid/current \
  --uid=byoid --gid=byoid \
  /usr/local/lib/node22/bin/node scripts/oauth-check.js
```

The transient unit lets systemd read the 0600 EnvironmentFile and pass the
environment to the checker without putting secrets in the shell argv. The
checker prints only modes and missing variable names. Do not use `cat` on the
env file or dump the service environment.

## Verify

```bash
curl -fsS https://byoid.rhobot.net/healthz
curl -fsS https://byoid.rhobot.net/api/config | jq '.providers[] | {id, mode}'
curl -sSI 'https://byoid.rhobot.net/auth/google/start?did=did:byoid:invalid'
```

The last request should redirect back to the app with an explanatory error, not
to Google, because the DID is invalid. For a valid wallet DID, a live provider
should redirect to the provider's authorization URL. In demo mode the server
redirects to `/?connect=<provider>`.

`/api/config` must never contain `clientSecret`, `applePrivateKey`, or any other
secret. It is intentionally a public endpoint.

## Rollback

```bash
readlink -f /opt/byoid/current
ls -1dt /opt/byoid/releases/*
ln -sfn /opt/byoid/releases/<previous> /opt/byoid/current.next
mv -Tf /opt/byoid/current.next /opt/byoid/current
systemctl restart byoid
```

The data directory is outside the release tree, so the agent key, deploy key and
in-memory session store state are not touched by a code rollback. Sessions are
in memory and are lost on any restart; users simply start OAuth again.

## Why the Pages app does not call this server

The Pages build is a separate origin. Live OAuth links the provider account to a
DID held in the browser's IndexedDB on that origin. The server cannot read that
browser-local wallet, and a static origin cannot safely hold the OAuth secrets.
Use **https://byoid.rhobot.net** for the full live-OAuth app; use the Pages build
for the zero-install demo and direct browser anchoring.
