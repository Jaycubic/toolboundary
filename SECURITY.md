# Security Policy

ToolBoundary is a security-relevant library. If you find a vulnerability —
especially anything that would let a denied action be allowed, a token be
forged or replayed, a provider authorization be bypassed, or the kill switch
be ignored — please report it privately rather than opening a public issue.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active (current stable release) |
| < 1.0   | ❌ No longer supported |

## Reporting

Open a private security advisory via GitHub:
`https://github.com/Jaycubic/toolboundary/security/advisories/new`

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce (a minimal code sample is ideal)
- Which version(s) of ToolBoundary are affected

We aim to acknowledge reports within a few days. Since this is a
community-maintained open source project (not a commercial product with
an SLA), response time may vary, but security reports are treated as the
highest priority.

## Scope

In scope:
- The core `Boundary` decision engine (`toolboundary.boundary`)
- The provider authorization flow (`toolboundary.provider`, `toolboundary.evidence`)
- The `EvidenceProvider` protocol and its interaction with local policy
- Token issuance/verification (`toolboundary.tokens`)
- The network enforcement proxy (`toolboundary.network`)
- The `@guarded_tool` decorator (`toolboundary.decorators`)
- The LangChain integration (`toolboundary.integrations.langchain`)
- Any scenario where a local DENY could be turned into an ALLOW by an
  external provider — this is explicitly prohibited by the architecture
  and would be treated as a critical vulnerability

Out of scope (see README "Known Limitations"):
- An agent bypassing ToolBoundary entirely by never calling through it —
  this is a documented architectural limitation of an application-layer
  library, not a bug. If you have ideas for closing this gap further
  (e.g. additional framework integrations, guidance on network
  segmentation), a GitHub discussion or PR is welcome — this is different
  from a vulnerability report about ToolBoundary's own logic being incorrect.
- Vulnerabilities in third-party dependencies (report those upstream;
  langchain-core is the only optional one currently).
- Provider-side vulnerabilities — if an `EvidenceProvider` implementation
  (e.g. AgentKey) has a bug, report it to the provider's maintainers.
  ToolBoundary's responsibility ends at enforcing the local policy and
  correctly invoking the provider protocol.
