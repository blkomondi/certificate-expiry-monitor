# Certificate Expiry Monitor: Project Structure

This is a Python command-line application. Run it from the project root, the folder that contains `checker`, `requirements.txt`, and `example_config.yaml`.

```text
CEM/
├── .venv/                         Local Python environment created during installation
├── checker/                       Application package; `python -m checker` starts here
│   ├── __init__.py                Declares the package and its public domain types
│   ├── __main__.py                Module entry point; calls the command-line program
│   ├── cli.py                     Parses commands/flags, configures logging, selects output
│   ├── config.py                  Loads YAML/JSON, expands ${ENVIRONMENT_VARIABLE}, applies flags
│   ├── models.py                  Dataclasses and enums: certificates, results, severities, errors
│   ├── evaluation.py              Pure UTC expiry calculation and severity decision rules
│   ├── parsing.py                 Reads PEM/DER bytes and extracts certificate metadata
│   ├── service.py                 Runs source checks concurrently and dispatches alerts
│   ├── state.py                   Persists alert history and suppression rules in JSON
│   ├── output.py                  Renders table, JSON, and Prometheus results
│   ├── sources/                   Ways to obtain certificates
│   │   ├── __init__.py            Exposes available source implementations
│   │   ├── base.py                Defines the extensible certificate-source interface
│   │   ├── tls.py                 Connects to host:port and retrieves a TLS leaf certificate
│   │   └── files.py               Loads certificate files, directories, and file globs
│   └── notification/              Ways to send already-decided alerts
│       ├── __init__.py            Exposes notification implementations
│       ├── base.py                Defines the notifier interface
│       ├── console.py             Writes readable alerts to stderr
│       └── webhook.py             Sends a small JSON alert payload to a configured webhook
├── tests/                         Deterministic pytest test suite; no external network calls
│   ├── conftest.py                Generates temporary certificates plus FakeClock/FakeNotifier
│   ├── test_evaluation.py         Time calculations, thresholds, and not-yet-valid behaviour
│   ├── test_parsing.py            PEM/DER metadata, fingerprints, CN, SAN extraction
│   ├── test_sources.py            File-source behaviour and TLS error mapping
│   ├── test_notifications.py      Console/webhook delivery and duplicate-alert prevention
│   ├── test_state.py              Alert escalation, force mode, state storage, suppressions
│   ├── test_service.py            Concurrency isolation and exit-code precedence
│   └── test_cli.py                CLI output and suppression commands
├── outputs/                       Downloadable handoff files
│   ├── certificate-expiry-monitor.zip  Complete portable project archive
│   └── INSTALLATION_README.md     Simple setup and use instructions
├── work/                          Scratch space; not needed to run the monitor
├── example_config.yaml            Editable example of targets, thresholds, state, and alerts
├── pyproject.toml                 Package metadata, Python version, dependencies, pytest config
├── requirements.txt               Dependencies for `pip install -r requirements.txt`
├── README.md                      Full operational guide, examples, automation, and limitations
└── PROJECT_STRUCTURE.md           This file
```

## How a certificate check flows

1. `cli.py` reads flags and optional configuration.
2. `service.py` schedules each target through `sources/tls.py` or `sources/files.py`.
3. `parsing.py` turns the certificate into a `CertInfo` object from `models.py`.
4. `evaluation.py` determines remaining days and severity using an injected UTC clock.
5. `output.py` writes every result to stdout.
6. `state.py` decides whether the tier has already been alerted and whether it is suppressed.
7. The files in `notification/` send eligible alerts to stderr or a webhook.

The `.venv` folder is generated locally and contains Python plus installed libraries; do not edit it. `work` is optional scratch space and can be ignored. The monitor's normal JSON alert-state file is created beside the project as `.certificate-monitor-state.json` after it runs with state enabled.
