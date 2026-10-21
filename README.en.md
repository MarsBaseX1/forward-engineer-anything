<div align="center">
  <img src="assets/fea-icon.png" alt="Forward Engineer Anything icon" width="160" />

# Forward Engineer Anything (FEA)

**Build forward. Raise the cost of reverse engineering.**

[简体中文](README.md) · English

</div>

FEA is an open-source protection engineering project for authors of Windows and macOS desktop software. It aims to reduce secrets and unnecessary implementation details shipped to clients, improve authorization and release boundaries, and measure the remaining risks with reproducible evidence.

> **Status: design stage.** This repository contains a product design, threat model, and roadmap. There is no runnable FEA CLI, npm package, or GitHub Action yet. All capabilities and milestones below are planned.

## Why FEA

AI-assisted analysis tools such as [REA](https://github.com/morluto/rea) make it easier to inspect distributed software. FEA helps software authors answer three practical questions:

- What does this release expose?
- Which protective changes produce measurable benefits?
- Has the next release reintroduced a known risk?

“Anything” describes the long-term adapter vision. Each release will support only explicitly documented inputs and checks.

FEA aims to reduce avoidable exposure and unauthorized use, and increase the cost of analysis and modification. Client-side code and observable behavior can still be analyzed or reimplemented. Obfuscation and integrity checks are additional defensive layers; they do not replace server-side authorization or sound trust boundaries.

## Four modules

| Module | Planned purpose | First milestone |
| --- | --- | --- |
| **Audit** | Inspect release resources without modifying them; report rules, evidence, confidence, and coverage. | v0.1 |
| **Protect** | Propose reviewable changes for supported build systems, with rollback and functional verification steps. | v0.2 |
| **Verify** | Enforce CI policies, then add final-artifact signature and release-integrity checks. | v0.1 policy gates; v0.2 platform checks |
| **Arena** | Compare baseline and hardened builds of owned demo applications under fixed analysis budgets. | v0.3 |

Deterministic rules will decide scan findings and CI policy outcomes. AI may explain evidence and suggest changes; scanning and policy gates will not require a model service.

## Planned v0.1 scope

The first release targets **developer-provided Electron release-resource directories** on Windows and macOS. Inputs must identify their stage as `prepackage` or `developer-extracted`.

Planned deliverables include a local CLI, versioned configuration, JSON and SARIF reports, configurable CI policy gates, and public synthetic test fixtures. Five check categories cover source maps, private-key format candidates, internal configuration, debug symbols, and development assets.

Candidate secrets will not be tested against live services. Reports must redact sensitive evidence, identify unassessed content and incomplete scans, and support documented exceptions with owners and expiry dates.

v0.1 will not read raw ASAR archives, parse EXE/MSI/DMG installers or native binaries, verify code signatures, modify projects, or provide runtime protection. A resource-directory scan does not establish the contents or security of a final installer. ASAR is an archive format, not a confidentiality boundary.

## Roadmap

- **v0.1 — Audit and CI policy gates:** resource scanning, structured reports, and reproducible fixtures.
- **v0.2 — Protect and platform verification:** bounded ASAR inspection, reviewable Electron Forge build changes, and Windows/macOS signature adapters.
- **v0.3 — Arena, MCP, and authorization reference:** owned demo applications, a reference authorization service, and an optional version-pinned REA evaluation adapter.
- **v0.4 — Native adapters and secure updates:** separately verified format adapters and integration with established update frameworks.

Milestones depend on acceptance evidence rather than calendar promises. An analysis timeout means a task did not succeed within its budget; it does not prove that software cannot be reverse engineered.

## Documentation

- [Product and architecture design](docs/superpowers/specs/2026-10-21-fea-design.md) (Chinese)
- [Threat model and protection boundaries](docs/THREAT_MODEL.md) (Chinese)
- [Release scope and acceptance criteria](docs/ROADMAP.md) (Chinese)

## License and responsible use

The project is licensed under [Apache-2.0](LICENSE). Third-party components retain their respective licenses. The design keeps protected application code, signing keys, customer data, and server secrets separately managed; using FEA does not require opening the protected application's source code.

FEA is independent of REA and is not affiliated with or endorsed by its maintainers. Evaluation targets must be owned by the operator or explicitly authorized for examination. The project respects legitimate interoperability, auditing, preservation, and security research.
