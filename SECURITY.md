# Security Reporting

## Supported Versions

Security fixes are applied to the current `main` branch and the latest tagged
release. Older releases should be upgraded before requesting backports.

## Reporting A Vulnerability

Report sensitive vulnerabilities privately through the repository's GitHub
Security Advisory interface or the private maintainer contact published on the
repository profile. Do not open a public issue containing exploit details,
credentials, license tokens, machine identifiers, customer data, or a working
sandbox escape.

Include the affected commit and feature set, host architecture and kernel,
reproduction steps, impact, and whether generated code, network access, FFI,
licensing, or persisted data is involved. Remove secrets and source content
that are not needed to reproduce the defect.

Maintainers will acknowledge receipt, reproduce and classify the report,
coordinate remediation and tests, and arrange disclosure after affected users
have an update. Publication timing depends on exploitability and deployment
impact; reporters are asked to avoid disclosure while a coordinated fix is in
progress.

## Security Scope

In scope for **this repository** are Enterprise admission, identity/RBAC/tenancy,
the governed MCP gateway and catalogue, durable store/journals, license and
revocation verification, persistence, CI/release provenance, and privacy
controls. The colocalized `core/` tree is in scope as the kernel Enterprise
depends on.

Out of scope here: CCOS Research Lab surfaces (`rsi.*`, `forge.*`, DGM,
generated-code execution, self-modification). Those products have their own
security process. Mentions of them in this tree are refusals or provenance,
not a claim that Enterprise sandboxes them.
