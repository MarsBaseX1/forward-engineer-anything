# Contributing to FEA

FEA is a stable open-source protection engineering framework for Electron desktop applications (v1.0.1). Contributions are welcome for rules, synthetic fixtures, adapters, documentation, and tests.

Please read [ROADMAP.md](docs/ROADMAP.md), [ANTI-REA-HARDENING.md](docs/ANTI-REA-HARDENING.md), and [THREAT_MODEL.md](docs/THREAT_MODEL.md) before proposing larger changes.

## How to contribute

1. Open an issue describing the user problem, target format, expected evidence, limitations, and acceptance criteria.
2. Pull requests should describe what changed and how it was verified.
3. Documentation-only changes need link and consistency checks.
4. Executable changes need relevant tests.

## Rules

- Use only software and fixtures you own or are authorized to examine.
- Do not include real credentials, signing keys, customer data, proprietary third-party binaries, or private analysis reports.
- Use synthetic values and minimized examples.
- Do not describe a technique as unbreakable or claim general protection based on a single failed analysis attempt.

The repository uses [Apache-2.0](LICENSE). Preserve third-party notices and disclose relevant dependencies.
