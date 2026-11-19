# CONFIGRA — Access Links

> This file documents how to expose CONFIGRA locally. Real machine-specific values
> (tunnel URLs, LAN IPs, network names) are intentionally not committed.

## The links

| Scope | URL | Notes |
|---|---|---|
| Any device, anywhere | `https://<your-tunnel>.trycloudflare.com` | Public tunnel. Changes each time the tunnel restarts. |
| This PC only | http://127.0.0.1:5000 | Always works locally |
| Same Wi-Fi | `http://<your-lan-ip>:5000` | May not work on hotspots with client isolation |

The public link opens straight to the scanner. A login gate exists in `app.py` and
activates only if `CONFIGRA_ACCESS_PASSWORD` is set in `.env`.

## Why a same-Wi-Fi link can fail

Many hotspot / guest Wi-Fi networks **isolate clients from each other** (AP/client
isolation): other devices appear in the ARP table but cannot be pinged.

This is not a firewall problem if:

- Python has an inbound `Allow` rule for the active profile, and
- CONFIGRA is listening on `0.0.0.0:5000`.

No IP/firewall change can fix client isolation. Use a tunnel instead.

## Start / stop

| Action | File |
|---|---|
| Start CONFIGRA | **`start_configra.bat`** |
| Start public tunnel | **`start_tunnel.bat`** |
| Stop tunnel | **`stop_tunnel.bat`** |
| Stop CONFIGRA | **`stop_configra.bat`** |

Typical order: `start_configra.bat` → `start_tunnel.bat` → copy the printed
`https://….trycloudflare.com` link.

## Important security notes

- A tunnel URL is **public on the internet**. Without a password, anyone who has the
  link can open CONFIGRA and start scans from your machine.
- Keep the link private. Never commit or post it.
- Quick tunnels are temporary: the URL changes on every restart, and Cloudflare may
  rate-limit them.
- Stop the tunnel when you are not using it (`stop_tunnel.bat`).
- To enable the login: set `CONFIGRA_ACCESS_PASSWORD=<password>` in `.env` and restart
  CONFIGRA. Local (`127.0.0.1`) access is never prompted.

## If you want a stable, permanent link later

Quick tunnels are for ad-hoc sharing. For a permanent address, use a named Cloudflare
Tunnel with your own domain (requires a free Cloudflare account and a domain), or ngrok
with a reserved domain. Both also support stronger access control than a shared password.
