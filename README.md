# SSL Certificate Monitor

A small, self-hosted web app that checks the SSL/TLS certificates of your websites and servers,
keeps track of them, and emails you before they expire.

- Web interface to add domains (`example.com`, `https://example.com`, `host:8443`)
- Automatic check (once every 24 hours by default) plus manual checks per domain or for all domains
- Detail view with validity, issuer, serial number, SHA-256/SHA-1 fingerprint, key type and size,
  signature algorithm, SANs, TLS version, cipher and IP address
- Email alarms per address with a configurable threshold (days), for one or all domains.
  One email per certificate; the alarm resets automatically after renewal
- Searchable history of all checks and sent alarm emails
- No database: everything is stored in two plain files
- Very light: Python + `cryptography`, no framework, roughly 30-50 MB RAM

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

```bash
mkdir ssl-monitor && cd ssl-monitor
curl -O https://raw.githubusercontent.com/YOUR-GITHUB-USERNAME/ssl-monitor/main/docker-compose.yml
curl -o .env https://raw.githubusercontent.com/YOUR-GITHUB-USERNAME/ssl-monitor/main/.env.example
nano .env                          # choose your own username and password
```

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

### 4. First-time configuration in the web interface

1. Under **Settings**, enter your SMTP server and send a test email.
2. Under **Domains**, add your sites.
3. Under **Email alarms**, add an address and a threshold (for example 14 days).

Gmail and Microsoft 365 require an app password. Use port 587 (STARTTLS), or port 465 with
"Direct SSL/TLS" checked.

## Environment variables (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_USER` | (required) | Username for the web interface (Basic Auth) |
| `AUTH_PASS` | (required) | Password for the web interface |
| `TZ` | `Europe/Amsterdam` | Time zone, used for the times in alarm emails |
| `BIND` | `127.0.0.1` | Address the port listens on at the host; `0.0.0.0` = whole network |
| `PORT` | `3082` | Port on the host |

The check interval, history retention and SMTP settings are configured in the web interface.

## Raspberry Pi tips

**Clock.** A Pi has no battery-backed clock. If the system time is wrong, the number of days until
expiry will be wrong too. Check with `timedatectl`; it should say `System clock synchronized: yes`.

**Memory limit.** If `docker compose up` warns that memory limits are not supported, the memory cgroup
is disabled in the kernel. Append the following to the end of the single line in
`/boot/firmware/cmdline.txt` (older OS versions: `/boot/cmdline.txt`), **on the same line**, and reboot:

```
cgroup_enable=memory cgroup_memory=1
```

Without this the application works fine, but the 96 MB limit is not enforced.

**SD card.** The application writes very little: a few lines per check and a small `data.json`.
With 25 domains and one check per day this is negligible for the lifetime of the card.

**Zero 2 W (512 MB).** Docker itself also uses memory. If you want the smallest footprint, run without
Docker (see below).

## Updating

```bash
docker compose pull && docker compose up -d
```

Your data lives in the `ssl-monitor-data` volume and is preserved.

## Data and backups

The application stores everything in `/data` inside the container:

| File | Contents |
|---|---|
| `data.json` | domains with their latest result, alarms, settings (**including the SMTP password in plain text**, mode `600`) |
| `history.jsonl` | one JSON line per check and per alarm email; append-only |

Backup:

```bash
docker run --rm -v ssl-monitor-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/ssl-monitor-$(date +%F).tgz -C /data .
```

Search the history from the command line:

```bash
docker compose exec ssl-monitor grep '"status":"error"' /data/history.jsonl
```

History is kept for 365 days by default (configurable; `0` = unlimited).

If you prefer a plain directory over a named volume, replace the volume with `./data:/data` and run
`mkdir data && sudo chown 10001:10001 data` once. Otherwise the container user has no write access.

## Running without Docker

Suitable for systems with little memory. Requires Python 3.8 or newer.

```bash
sudo apt install python3 python3-cryptography
sudo mkdir -p /opt/ssl-monitor
sudo cp -r server.py public /opt/ssl-monitor/
```

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
Environment=AUTH_USER=admin
Environment=AUTH_PASS=choose-a-long-password
Environment=TZ=Europe/Amsterdam
DynamicUser=yes
StateDirectory=ssl-monitor
Restart=always

[Install]
WantedBy=multi-user.target
```

With `DynamicUser=yes`, `StateDirectory` points to `/var/lib/ssl-monitor`, which matches `DATA_DIR`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssl-monitor
```

## Security

- The web interface uses **Basic Auth**. Over plain HTTP the password is sent unencrypted.
  Outside your own trusted network, always put a reverse proxy with HTTPS in front of it
  (Caddy, nginx, Traefik).
- The server itself opens connections to the hosts you configure. Do not expose it to the internet
  without a login.
- The SMTP password is stored unencrypted in `data.json`. Keep the volume private and include it in
  your backup policy.
- The container runs as a non-root user.

## Building yourself

```bash
# for your own architecture
docker build -t ssl-monitor .

# both architectures (for example to build for a Pi on a PC)
docker buildx build --platform linux/amd64,linux/arm64 -t ssl-monitor .
```

To build locally instead of using the image from GitHub, replace the `image:` line in
`docker-compose.yml` with `build: .`.

## Publishing via GitHub

On every push to `main`, the GitHub Action builds and publishes an image for amd64 and arm64 to
`ghcr.io/<user>/ssl-monitor`. To make a versioned release:

```bash
git tag v1.0.0 && git push --tags
```

This produces the tags `1.0.0`, `1.0` and `latest`.

A new ghcr.io package is private by default. To make it public: GitHub → your profile → *Packages* →
`ssl-monitor` → *Package settings* → *Change visibility*. Image names must be lowercase.

## API

All endpoints require the same Basic Auth, except `/healthz`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Health check (no login) |
| GET | `/api/state` | Domains, alarms and settings |
| POST | `/api/domains` | Add a domain: `{"url": "example.com"}` |
| DELETE | `/api/domains/<id>` | Delete a domain and its alarms (history is kept) |
| POST | `/api/domains/<id>/check` | Check one domain now |
| POST | `/api/check-all` | Check all domains now |
| POST | `/api/alarms` | Add an alarm: `{"email", "days", "domainId"}` (`"all"` for all domains) |
| DELETE | `/api/alarms/<id>` | Delete an alarm |
| PUT | `/api/settings` | Save settings |
| POST | `/api/settings/test-email` | Send a test email: `{"to": "..."}` |
| GET | `/api/history` | Search history: `q`, `domainId`, `type`, `status`, `from`, `to`, `limit`, `offset` |

## Troubleshooting

| Problem | Solution |
|---|---|
| `exec format error` or `no matching manifest` | Your OS is 32-bit. Check `uname -m`; only `aarch64` and `x86_64` are supported. Install 64-bit Raspberry Pi OS |
| Container does not start: `AUTH_USER` missing | Create `.env` (see `.env.example`) |
| `unauthorized` on `docker pull` | The image is private: `docker login ghcr.io` with a token that has `read:packages` |
| Permission denied on `/data` | With a bind mount: `sudo chown 10001:10001 ./data` |
| Domain shows `DNS lookup failed` | DNS does not work from inside the container; try `network_mode: host` instead of `ports:` |
| Wrong number of "days remaining" | The system clock is wrong (see Raspberry Pi tips) |
| No alarm email | Check **History** (type *Alarm emails*): failed attempts are listed with the error message |
| Email fails with Gmail/M365 | Use an app password and the correct port/TLS setting |

## License

Choose a license (for example MIT) and add a `LICENSE` file.
