# SSL Certificate Monitor

A small, self-hosted web app that checks the SSL/TLS certificates of your websites and servers,
keeps track of them, and emails you before they expire.

- Web interface to add domains (`example.com`, `https://example.com`, `host:8443`)
- Automatic check (once every 24 hours by default) plus manual checks per domain or for all domains
- Edit domains after adding them (host/port, or name and certificate for uploaded entries)
- Track certificates that are not reachable over the network by uploading them
  (PEM text, or a `.cer` / `.crt` / `.pem` / `.der` file)
- Detail view with validity, issuer, serial number, SHA-256/SHA-1 fingerprint, key type and size,
  signature algorithm, SANs, TLS version, cipher and IP address
- Email alarms per address with a configurable threshold (days), for one or all domains.
  One email per certificate; the alarm resets automatically after renewal
- Searchable history of all checks and sent alarm emails
- SMTP is configured through environment variables only, never through the web interface
- No database: everything is stored in two plain files
- Very light: Python + `cryptography`, no framework

## Supported systems

| System | Operating system | Image |
|---|---|---|
| Raspberry Pi 5, Pi 4, Pi Zero 2 W | **64-bit** Raspberry Pi OS / Linux (`uname -m` → `aarch64`) | `linux/arm64` |
| PC / server / VM | 64-bit Linux, macOS, Windows (Docker Desktop) | `linux/amd64` |

Docker picks the right variant automatically. 32-bit systems (`armv7l`, `armv6l`) are **not** supported.
If your Pi still runs a 32-bit operating system, install 64-bit Raspberry Pi OS.

## Quick start with Docker

### 1. Install Docker (once)

On a Raspberry Pi or any other Linux system:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER      # then log out and back in
```

### 2. Get the configuration

Run these as your normal user, **not** with `sudo`:

```bash
mkdir ssl-monitor && cd ssl-monitor
curl -O https://raw.githubusercontent.com/YOUR-GITHUB-USERNAME/ssl-monitor/main/docker-compose.yml
curl -o .env https://raw.githubusercontent.com/YOUR-GITHUB-USERNAME/ssl-monitor/main/.env.example
mkdir -p data                      # create it yourself, so it is not owned by root
printf "PUID=%s\nPGID=%s\n" "$$(id -u)" "$$(id -g)" >> .env
chmod 600 .env                     # .env contains passwords
nano .env                          # set AUTH_USER, AUTH_PASS and the SMTP_* values
```

`.env.example` already contains `PUID=1000` and `PGID=1000`. If your IDs differ (check with `id -u` and
`id -g`), remove the duplicate lines and keep the correct ones.

If the image is private in GitHub Packages, log in once with a Personal Access Token that has the
`read:packages` scope:

```bash
echo "<token>" | docker login ghcr.io -u YOUR-GITHUB-USERNAME --password-stdin
```

### 3. Start

```bash
docker compose up -d
docker compose logs -f
```

Open `http://<ip-of-the-device>:3082` (or `http://localhost:3082` on the same machine).
By default the container only listens on `127.0.0.1`. Set `BIND=0.0.0.0` in `.env` to make it
reachable from your network.

### 4. First-time configuration

1. Set your SMTP server in `.env` (see *Environment variables*) and run `docker compose up -d` again.
   The **Settings** card in the web interface shows the active SMTP configuration (read-only);
   use *Send test email* to verify it.
2. Under **Domains**, add your sites.
3. Under **Email alarms**, add an address and a threshold (for example 14 days).

Gmail and Microsoft 365 require an app password. Use port 587 (`starttls`), or port 465 (`ssl`).

## Environment variables (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_USER` | (required) | Username for the web interface (Basic Auth) |
| `AUTH_PASS` | (required) | Password for the web interface |
| `TZ` | `Europe/Amsterdam` | Time zone, used for the times in alarm emails |
| `PUID` | `1000` | User ID the container runs as (output of `id -u`); owner of the files in `./data` |
| `PGID` | `1000` | Group ID the container runs as (output of `id -g`) |
| `BIND` | `127.0.0.1` | Address the port listens on at the host; `0.0.0.0` = whole network |
| `PORT` | `3082` | Port on the host (inside the container the app always listens on 3082) |
| `SMTP_HOST` | (empty) | SMTP server. Empty disables email |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_SECURITY` | `starttls` (`ssl` on port 465) | `starttls`, `ssl` or `none` |
| `SMTP_USER` | (empty) | SMTP username. Empty = no authentication |
| `SMTP_PASS` | (empty) | SMTP password |
| `SMTP_FROM` | `SMTP_USER` | Sender address |

The check interval and history retention are configured in the web interface. **SMTP settings can only be
set through environment variables** (`.env` or `docker-compose.yml`) and are deliberately not editable in
the web interface. Wrap values containing `$` or `#` in single quotes. After changing `.env`, run
`docker compose up -d` to apply it.

With `SMTP_SECURITY=starttls`, STARTTLS is mandatory: if the server does not support it, sending fails
instead of sending your password unencrypted. Use `none` only for a trusted local relay.

## Uploaded certificates

Not every certificate is reachable over the network (internal services, client certificates, certificates
you only have as a file). Click **Add certificate** to track such a certificate:

- upload a `.cer`, `.crt`, `.pem` or `.der` file, or paste the PEM text;
- if you paste or upload a chain, only the first certificate is used;
- files containing a private key are rejected. Never upload private keys.

Uploaded certificates get a status based on their expiry date, work with email alarms, and appear in the
history, but they are **not checked over the network** and their **trust is not verified** (there is no
chain to verify against). Use **Edit** to rename the entry or to replace the certificate after renewal;
replacing it resets the alarm state for that entry.

To change the host or port of a normal domain, use **Edit** as well.

## Raspberry Pi tips

**Clock.** A Pi has no battery-backed clock. If the system time is wrong, the number of days until
expiry will be wrong too. Check with `timedatectl`; it should say `System clock synchronized: yes`.

**SD card.** The application writes very little: a few lines per check and a small `data.json`.
With 25 domains and one check per day this is negligible for the lifetime of the card.

**Zero 2 W (512 MB).** Docker itself also uses memory. If you want the smallest footprint, run without
Docker (see below).

## Updating

```bash
docker compose pull && docker compose up -d
```

Your data lives in the `./data` directory and is preserved.

## Data and backups

The application stores everything in `./data` (mounted at `/data` in the container). The files belong to
the user set by `PUID`/`PGID`, so you can read and copy them without `sudo`.

| File | Contents |
|---|---|
| `data.json` | domains with their latest result, uploaded certificates (public part only), alarms, settings (mode `600`) |
| `history.jsonl` | one JSON line per check and per alarm email; append-only |

Backup:

```bash
tar czf ssl-monitor-$(date +%F).tgz data
```

Search the history from the command line:

```bash
grep '"status":"error"' data/history.jsonl
```

History is kept for 365 days by default (configurable; `0` = unlimited).

Deleting a domain keeps its history. To remove it as well, stop the container and filter the file, for
example: `jq -c 'select(.host!="example.com")' data/history.jsonl > new && mv new data/history.jsonl`.

## Running without Docker

Suitable for systems with little memory. Requires Python 3.8 or newer.

```bash
sudo apt install python3 python3-cryptography
sudo mkdir -p /opt/ssl-monitor
sudo cp -r server.py public /opt/ssl-monitor/
```

Put the configuration in `/etc/ssl-monitor.env` (owner root, `sudo chmod 600`):

```
AUTH_USER=admin
AUTH_PASS=choose-a-long-password
TZ=Europe/Amsterdam
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=ssl-monitor@example.com
SMTP_PASS=your-smtp-password
SMTP_FROM=ssl-monitor@example.com
```

Do not use quotes around values here: systemd interprets them differently than Docker Compose.

`/etc/systemd/system/ssl-monitor.service`:

```ini
[Unit]
Description=SSL Monitor
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/ssl-monitor
ExecStart=/usr/bin/python3 server.py
Environment=DATA_DIR=/var/lib/ssl-monitor
EnvironmentFile=/etc/ssl-monitor.env
DynamicUser=yes
StateDirectory=ssl-monitor
Restart=always

[Install]
WantedBy=multi-user.target
```

systemd reads the environment file as root, so `DynamicUser=yes` keeps working. With `DynamicUser=yes`,
`StateDirectory` points to `/var/lib/ssl-monitor`, which matches `DATA_DIR`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssl-monitor
```

The app listens on port 3082 by default (set `PORT` to change it).

## Security

- The web interface uses **Basic Auth**. Over plain HTTP the password is sent unencrypted.
  Outside your own trusted network, always put a reverse proxy with HTTPS in front of it
  (Caddy, nginx, Traefik).
- The server itself opens connections to the hosts you configure. Do not expose it to the internet
  without a login, and only give access to people you trust: anyone who can log in can make the server
  connect to any host and port it can reach.
- The SMTP password lives only in `.env` (or your compose file), never in `data.json` or the web
  interface. Keep `.env` private (`chmod 600 .env`) and out of Git.
- Uploaded certificates are stored as public certificates only. Files containing a private key are
  rejected.
- The container runs as a non-root user (your `PUID`/`PGID`).

## Building yourself

```bash
# for your own architecture
docker build -t ssl-monitor .

# both architectures (for example to build for a Pi on a PC)
docker buildx build --platform linux/amd64,linux/arm64 -t ssl-monitor .
```

To build locally instead of using the image from GitHub, replace the `image:` line in
`docker-compose.yml` with `build: .` and run `docker compose up -d --build`.

## Publishing via GitHub

On every push to `main`, the GitHub Action builds and publishes an image for amd64 and arm64 to
`ghcr.io/<user>/ssl-monitor`. To make a versioned release:

```bash
git tag v1.0.0 && git push --tags
```

This produces the tags `1.0.0`, `1.0` and `latest`.

A new ghcr.io package is private by default. To make it public: GitHub → your profile → *Packages* →
`ssl-monitor` → *Package settings* → *Change visibility*. Image names must be lowercase.

Before pushing, check with `git status` that `.env`, `data/`, `data.json` and `history.jsonl` are not
included.

## API

All endpoints require the same Basic Auth, except `/healthz`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Health check (no login) |
| GET | `/api/state` | Domains, alarms, settings and the read-only SMTP status |
| POST | `/api/domains` | Add a domain `{"url": "example.com"}`, or an uploaded certificate `{"source": "upload", "name": "...", "certificate": "<PEM text or base64 DER>"}` |
| PUT | `/api/domains/<id>` | Edit a domain `{"url"}`, or an uploaded certificate `{"name", "certificate"}` (certificate optional) |
| DELETE | `/api/domains/<id>` | Delete a domain and its alarms (history is kept) |
| POST | `/api/domains/<id>/check` | Check one domain now |
| POST | `/api/check-all` | Check all domains now |
| POST | `/api/alarms` | Add an alarm: `{"email", "days", "domainId"}` (`"all"` for all domains) |
| DELETE | `/api/alarms/<id>` | Delete an alarm |
| PUT | `/api/settings` | Save check interval and history retention (`intervalHours`, `historyDays`) |
| POST | `/api/settings/test-email` | Send a test email: `{"to": "..."}` |
| GET | `/api/history` | Search history: `q`, `domainId`, `type`, `status`, `from`, `to`, `limit`, `offset` |

## Troubleshooting

| Problem | Solution |
|---|---|
| `exec format error` or `no matching manifest` | Your OS is 32-bit. Check `uname -m`; only `aarch64` and `x86_64` are supported. Install 64-bit Raspberry Pi OS |
| Container does not start: `AUTH_USER` missing | Create `.env` (see `.env.example`) |
| `unauthorized` on `docker pull` | The image is private: `docker login ghcr.io` with a token that has `read:packages` |
| Permission denied on `/data`, or `./data` is owned by root | Create the directory yourself before the first start (`mkdir data`), set `PUID`/`PGID` in `.env` to `id -u` / `id -g`, and fix existing files with `sudo chown -R "$(id -u):$(id -g)" data` |
| Domain shows `DNS lookup failed` | DNS does not work from inside the container; try `network_mode: host` instead of `ports:` |
| Wrong number of "days remaining" | The system clock is wrong (see Raspberry Pi tips) |
| Settings shows "SMTP is not configured" | Set `SMTP_HOST` (and the other `SMTP_*` variables) in `.env`, then `docker compose up -d` |
| Test email fails with a TLS error | Match `SMTP_SECURITY` to the port: `starttls` for 587, `ssl` for 465 |
| Email fails with Gmail/M365 | Use an app password and the matching `SMTP_PORT` / `SMTP_SECURITY` |
| SMTP password with `$` or `#` does not work | Wrap it in single quotes in `.env`: `SMTP_PASS='pa$$word#1'` |
| No alarm email | Check **History** (type *Alarm emails*): failed attempts are listed with the error message |
| "Could not read the certificate" | Upload a certificate (not a key or CSR) as PEM or DER; for `.p12`/`.pfx` files extract it first: `openssl pkcs12 -in file.p12 -clcerts -nokeys -out cert.pem` |

## License

[MIT](LICENSE)
