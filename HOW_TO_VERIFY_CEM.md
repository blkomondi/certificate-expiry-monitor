# How to Verify CEM Is Up and Running — Handoff Guide

This guide is for handing to a colleague who needs to **get the CEM (Certificate
Expiry Monitor) files** and **verify the monitor and the registry image are
working**. It assumes a Windows machine on the Sidian Bank network (or VPN).

---

## 0. Prerequisites (check these first)

- [ ] You are on the bank network or VPN.
- [ ] You can reach the registry server (run this):
      `ping 192.168.200.13`
      → you should see `Reply from 192.168.200.13`.
- [ ] **For the Python method:** Python 3.12 installed.
      Check with `python --version` (if "not recognized", install Python 3.12
      from python.org and tick **"Add python.exe to PATH"** during setup).
- [ ] **For the Docker method:** Docker Desktop installed and running.
      Check with `docker --version`.

> **Note on credentials:** No login is needed for the registry or for checking
> the URLs. SSH root access to the servers is handled separately by the CEM
> administrator — do not ask the machine owner for it.

---

## 1. Get the CEM files

### Option A — Clone from GitHub (cleanest)

```cmd
git clone https://github.com/blkomondi/certificate-expiry-monitor.git
cd certificate-expiry-monitor
```

### Option B — Copy from the source machine

Copy the whole project folder from:
`C:\Users\Admin\Documents\Codex\2026-07-27\CEM`
(e.g. via a USB drive or network share), then open a command prompt in that folder.

> **Note:** The file `config.yaml` (with the two Sidian eCollect URLs and
> notification settings) **is included in the repo**, so Option A gives you
> everything out of the box. If you prefer to build your own, copy
> `example_config.yaml` to `config.yaml` and edit the `targets` section to:
>    ```yaml
>    targets:
>      - type: url
>        url: "https://ecollectv2.sidianbank.co.ke/"
>      - type: url
>        url: "https://ecollectuat.sidianbank.co.ke/"
>      - type: url
>        url: "https://ecollectdev.sidianbank.co.ke/"
>      - type: url
>        url: "https://keycloakdev.sidianbank.co.ke/"
>    ```

---

## 2. Quick sanity check — is CEM already in the registry? (no Docker needed)

The registry is plain HTTP (not HTTPS) and requires no login. From any cmd:

```cmd
curl http://192.168.200.13:32000/v2/cem/tags/list
```

**Expected output** (proves the image was pushed):

```
{"name":"cem","tags":["20260813"]}
```

You should also see `cem-sid` with `latest`:

```cmd
curl http://192.168.200.13:32000/v2/_catalog
```

**If you get `404`** → the image was never pushed.
**If `curl` gives an SSL error** → you used `https://`; the registry is HTTP,
use `http://`.

---

## 3. Test CEM locally with Python (no Docker needed)

From the project folder (in cmd):

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m checker --config config.yaml
```

If `config.yaml` isn't available, test a single URL directly:

```cmd
python -m checker --url https://ecollectv2.sidianbank.co.ke/ --format json
```

### What "working" looks like (expected output)

A table (or JSON) with **four rows**, one per URL, like:

| Target | Status | Expires | Days left |
|---|---|---|---|
| ecollectv2.sidianbank.co.ke | OK / VALID | 2026-12-19 | 128 |
| ecollectuat.sidianbank.co.ke | OK / VALID | 2026-12-19 | 128 |
| ecollectdev.sidianbank.co.ke | OK / VALID | 2027-06-30 | 320 |
| keycloakdev.sidianbank.co.ke | OK / VALID | 2027-06-30 | 320 |

- `status: OK` and `normalized_status: VALID` → **CEM is working**.
- `chain_valid: false` is **expected and fine** — the servers don't send the
  full intermediate certificate chain; the leaf certificate still validates.
- Any error/`expired` status → investigate (see Troubleshooting).

---

## 4. Test the registry image with Docker (proves the deployed image runs)

### Step 4a — Tell Docker the registry is insecure (HTTP, no TLS)

Docker refuses HTTP registries by default, so configure it once:

1. Open **Docker Desktop** → **Settings** → **Docker Engine**.
2. Add this line to the JSON (before the closing `}`):
   ```json
   "insecure-registries": ["192.168.200.13:32000"]
   ```
3. Click **Apply & Restart**.

### Step 4b — Pull the image

```cmd
docker pull 192.168.200.13:32000/cem:20260813
```

**Expected:** a list of layers downloading, ending with a success line.

### Step 4c — Run the image (the real "is it up and running" test)

```cmd
docker run --rm 192.168.200.13:32000/cem:20260813 check --url https://ecollectv2.sidianbank.co.ke/ --format json
```

**Expected:** the same JSON as Step 3 — `"status": "OK"`,
`"days_remaining": 128`. If you see that, the image in the registry is
**complete and runs correctly**.

---

## 5. (If deployed) Check the 24/7 monitor on the server

Only relevant if the monitor has been deployed to `192.168.200.13` / `.14`.
Ask the CEM administrator for SSH access, then:

```cmd
ssh root@192.168.200.13
docker ps | grep cem
docker logs cem-monitor --tail 20
cat /app/data/certificate-monitor-state.json
```

**Expected:**
- `docker ps` shows a `cem-monitor` container that has been up (not exited).
- `docker logs` shows a recent check per URL (every 6 hours), e.g.
  `certificate expires in 128 day(s)`.
- The state JSON file exists and contains entries for all four URLs.

---

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `'docker' is not recognized` | Docker Desktop not running/installed | Start Docker Desktop, wait for "Engine running" |
| `http: server gave HTTP response to HTTPS client` | Insecure registry not configured | Do Step 4a (add `insecure-registries`) |
| `curl` SSL certificate error | Used `https://` on the registry | Use `http://192.168.200.13:32000` |
| `Request timed out` / ping fails | Not on the bank network/VPN | Connect to the office network or VPN |
| `curl: (7) Failed to connect` on port 32000 | Registry service down | Contact the CEM/IT administrator |
| `manifest unknown` when pulling | Wrong tag name | Use the tag from Step 2 (`20260813` or `latest`) |
| `'python' is not recognized` | Python not installed / not on PATH | Install Python 3.12, tick "Add to PATH", reopen cmd |
| Check reports `chain_valid: false` | Servers omit intermediate cert | Expected — ignore; leaf cert is valid |
| Alerts not sending | `.env` missing/empty | Fill `.env` from `.env.example` (SendGrid key + recipient) |

---

## 7. One-line summary of what "working" means

1. `curl http://192.168.200.13:32000/v2/cem/tags/list` returns `cem` + a tag → **image in registry** ✅
2. `python -m checker --config config.yaml` shows both URLs `VALID` → **CEM checks work** ✅
3. `docker run .../cem:20260813 check --url ...` returns `OK` → **registry image runs** ✅
