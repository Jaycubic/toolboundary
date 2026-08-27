# Security Policy

ToolBoundary is a security-relevant library. If you find a vulnerability —
especially anything that would let a denied action be allowed, a token be
forged or replayed, or the kill switch be ignored — please report it
privately rather than opening a public issue.

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
- Token issuance/verification (`toolboundary.tokens`)
- The network enforcement proxy (`toolboundary.network`)
- The LangChain integration (`toolboundary.integrations.langchain`)

Out of scope (see README "Known Limitations"):
- An agent bypassing ToolBoundary entirely by never calling through it —
  this is a documented architectural limitation of an application-layer
  library, not a bug. If you have ideas for closing this gap further
  (e.g. additional framework integrations, guidance on network
  segmentation), a GitHub discussion or PR is welcome — this is different
  from a vulnerability report about ToolBoundary's own logic being incorrect.
- Vulnerabilities in third-party dependencies (report those upstream;
  langchain-core is the only optional one currently).
