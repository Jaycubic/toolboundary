# Security Policy

ToolBoundary is a security-relevant library. If you discover a vulnerability,
please report it privately rather than opening a public issue. Reports are
especially important if they could allow a denied action to execute, forge or
replay an authorization token, bypass provider authorization, evade network
enforcement, or disable the kill switch.

## Supported versions

| Version | Security support |
|---------|------------------|
| 1.0.5   | Supported — latest release |
| Earlier 1.0.x releases | Upgrade to 1.0.5; fixes are not backported by default |
| < 1.0   | Not supported |

Please reproduce issues against the latest release where possible. If an older
release is affected, include the exact version and a minimal reproduction.

## Reporting a vulnerability

Open a private security advisory through GitHub:

https://github.com/Jaycubic/toolboundary/security/advisories/new

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal code sample is ideal)
- The affected ToolBoundary version(s)
- Any relevant framework, Python, operating-system, or deployment details
- A suggested mitigation, if you have one

Please do not publish exploit details or open a public issue before a fix or
coordinated disclosure has been agreed. We aim to acknowledge reports within a
few days. ToolBoundary is a community-maintained open-source project and does
not provide a commercial security-response SLA; response time may vary, but
security reports are treated as a priority.

## Scope

The following project components and security properties are in scope:

- Core policy evaluation and authorization (`toolboundary.boundary`)
- Permission, operation allow-list, numeric-limit, approval, rate-limit, and
  kill-switch enforcement
- Provider authorization and execution-evidence lifecycle
  (`toolboundary.provider`, `toolboundary.evidence`)
- The `EvidenceProvider` contract and the invariant that an external provider
  cannot turn a local DENY into an ALLOW
- Authorization-token issuance, signing, verification, expiry, and replay
  prevention (`toolboundary.tokens`)
- Network proxy routing, upstream validation, request handling, and token
  enforcement (`toolboundary.network`)
- Audit handling and sensitive-argument redaction (`toolboundary.audit`,
  `toolboundary.decorators`)
- Framework adapters and their enforcement paths:
  - LangChain (`toolboundary.integrations.langchain`)
  - CrewAI (`toolboundary.integrations.crewai`)
- Shared Redis rate-limiter and token-store implementations
  (`toolboundary.redis_backend`), including fail-closed behaviour
- Any defect that causes a configured security control to be silently skipped,
  weakened, or incorrectly reported

The central security invariant is that a local DENY is final. An external
provider, framework adapter, or integration must never convert that decision
into an ALLOW.

## Out of scope

The following are not, by themselves, vulnerabilities in ToolBoundary:

- **Application code that bypasses ToolBoundary.** If an application calls a
  tool's underlying implementation directly instead of routing execution
  through a guarded function, guarded framework tool, or the network
  enforcement layer, ToolBoundary cannot evaluate that call. This is a
  documented architectural limitation of an in-process, application-layer
  library. See the README's "Known limitations" section.
- **Third-party dependency vulnerabilities.** Report vulnerabilities in
  dependencies such as LangChain, CrewAI, or redis-py to their respective
  maintainers. A ToolBoundary-specific integration defect that exposes or
  triggers a security bypass remains in scope.
- **Provider-side vulnerabilities.** If an external `EvidenceProvider`
  implementation (for example, an AgentKey service or SDK) has a defect,
  report it to that provider's maintainers. A defect in ToolBoundary's own
  provider contract or its enforcement of provider decisions remains in scope.
- **Deployment controls outside this repository.** Firewall, cloud IAM,
  credential-management, and host-hardening misconfigurations are the
  responsibility of the deployment. ToolBoundary documentation may recommend
  these controls, but does not itself configure them.

For questions, feature requests, or general hardening suggestions that do not
describe a vulnerability, use the repository's public GitHub discussions or
issues.
