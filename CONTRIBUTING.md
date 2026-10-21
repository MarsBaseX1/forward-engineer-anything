# Contributing to FEA

FEA is currently a design-stage project. There is no released CLI or protection runtime. Contributions should keep planned capabilities clearly separate from implemented and verified behavior.

Useful first contributions include reviewing the threat model, refining the v0.1 resource rules, proposing synthetic positive and negative fixtures, and documenting supported Windows / macOS build layouts. Read the [architecture design](docs/superpowers/specs/2026-10-21-fea-design.md) and [roadmap](docs/ROADMAP.md) before proposing a new subsystem.

Open an issue to explain the user problem, target format, expected evidence, limitations, and acceptance criteria. Pull requests should describe what changed and how it was checked. Documentation-only changes need link and consistency checks; executable changes need tests relevant to their behavior.

Use only software and fixtures you own or are authorized to examine. Do not include real credentials, signing keys, customer data, proprietary third-party binaries, or private analysis reports in issues, pull requests, or test fixtures. Use synthetic values and minimized examples.

The repository uses [Apache-2.0](LICENSE). Preserve third-party notices and disclose relevant dependencies. Do not describe a technique as unbreakable or claim general protection based on a single failed analysis attempt.
