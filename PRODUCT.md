<!-- impeccable:product-schema 1 -->

# GeekNosy — Product truth

## Product

- **Name:** GeekNosy
- **Platform:** Web application, REST API and CLI, deployed with Docker.
- **Creator:** Favio Urrea / [@FavinhoJR](https://github.com/FavinhoJR).
- **Purpose:** Defensive, evidence-first web posture assessment for assets owned by the operator or explicitly authorized for testing.

## Confirmed facts

- The existing product already performs public HTTP, TLS and DNS checks and must keep those capabilities working.
- The primary use cases are rapid audits, bug-bounty reconnaissance and repeatable security automation.
- Passive checks are the default operating mode.
- Checks that require credentials, consent or more intrusive requests must be separated and enabled only when needed.
- The product must run consistently through Docker and install its runtime dependencies during image builds.
- Public-facing product copy should stay concise; detailed capabilities and operational guidance belong in dedicated documentation.
- The interface must clearly communicate scope, authorization requirements and operational risk.

## Inferred product decisions

- **Primary audience:** Security practitioners who understand scope and authorization but need a fast, legible operational workspace.
- **Core promise:** Turn public evidence into prioritized, reproducible findings without silently crossing the operator's authorized boundary.
- **Primary action:** Start a passive assessment of one or more in-scope domains.
- **Secondary actions:** Review evidence, compare history, export reports, schedule recurring scans and deliberately enter an authorized assessment workspace.
- **Default tone:** Precise, calm and operational; never theatrical or alarmist.
- **Default density:** Compact enough for professional use, with progressive disclosure for advanced controls.

## Safety and trust boundaries

- Private, loopback, link-local, multicast and reserved destinations remain blocked by default.
- Every scan requires an authorization attestation.
- Authenticated or active checks require a separate Docker profile, an explicit runtime opt-in and a second confirmation in the UI/API.
- Secrets, authorization headers, cookies and sensitive response material must be redacted from stored evidence and logs.
- Findings are signals for human validation, not claims of exploitability.
- Rate limits, same-origin redirect controls, response limits and cancellation must remain enforceable.

## Brand principles

- GeekNosy feels like an evidence desk: ordered, candid, fast to scan and unmistakably built for accountable security work.
- Severity is communicated with labels, icons and language as well as color.
- Strong contrast, visible focus and keyboard access are product requirements.
- The interface avoids generic neon-cyber decoration, terminal cosplay and decorative gradients.

## Success criteria

- A first-time operator can distinguish passive and authorized modes before launching a scan.
- The default Docker stack starts with one documented command and reports healthy services.
- An operator can trace every finding to evidence, severity, confidence, standards mapping and remediation.
- Advanced or authenticated work cannot run accidentally from the default service profile.
- The responsive interface remains usable at 390 px, 1440 px and wide desktop viewports.
