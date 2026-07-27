# Certificate Expiry Monitor — Installation & Use

## Where to run it

You already have a runnable copy in:

```text
C:\Users\Admin\Documents\Codex\2026-07-27\CEM
```

Open PowerShell in that folder. You do **not** need to extract the ZIP to use this copy.

The ZIP is only for moving the project to another computer or folder. If you use the ZIP, extract it first and open PowerShell in the extracted folder—the correct folder contains `checker`, `requirements.txt`, and `example_config.yaml`.

## Install (Windows PowerShell)

Run these commands once from the project folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell prevents activation, run this once in the same window and retry:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Check a website

With the virtual environment activated, run:

```powershell
python -m checker --domain youtube.com:443
```

This checks YouTube's public TLS certificate. `youtube.com` is not hardcoded; replace it with any hostname and port:

```powershell
python -m checker --domain example.org:443
python -m checker --domain api.example.org:8443
python -m checker --domain example.org:443 --domain api.example.org:443
```

IPv4 and IPv6 targets work too:

```powershell
python -m checker --domain 192.0.2.10:443
python -m checker --domain [2001:db8::10]:443
```

## Output formats

The default is a readable table:

```powershell
python -m checker --domain youtube.com:443
```

Use JSON for scripts:

```powershell
python -m checker --domain youtube.com:443 --format json
```

Use Prometheus metrics:

```powershell
python -m checker --domain youtube.com:443 --format prometheus
```

## Use a configuration file

Open `example_config.yaml` in a text editor and replace the sample targets with your own. Then run:

```powershell
python -m checker --config example_config.yaml
```

The configuration supports remote TLS targets, local PEM/DER certificate files, file globs, configurable thresholds, concurrency, timeouts, and optional webhook alerts.

## Useful commands

```powershell
python -m checker --help
python -m checker --domain youtube.com:443 --dry-run
python -m checker --domain youtube.com:443 --force-notify
python -m checker suppress --target youtube.com:443 --reason "maintenance"
python -m checker unsuppress --target youtube.com:443
```

`--dry-run` checks certificates and identifies alerts without sending notifications or changing saved alert state.

## Run tests

```powershell
pytest
```

## Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m checker --domain youtube.com:443
```
