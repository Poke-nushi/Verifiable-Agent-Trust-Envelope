# Standards and Ecosystem Landscape for This Draft
## As of 2026-04-19

## Conclusion

This draft is credible as a protocol discussion topic because the surrounding building blocks already exist in fragmented form.
Major vendors are also starting to package those fragments into product layers.
The Salesforce 2026-04-15 Headless 360 and Agent Fabric announcements are a strong example of that shift.

What exists today:

- A2A for agent discovery and delegation
- MCP and OAuth-based authorization for tool access
- VC, OpenID, and workload identity building blocks for identity and proof
- status and risk signaling mechanisms
- emerging product signals around agent verification and agent payment

What is still missing is a portable, cross-vendor object model for expressing:

- who the actor is
- on whose behalf it is acting
- which runtime is involved
- what is permitted for the current task
- what receipt should exist afterward
- how status, suspension, or revocation should propagate

This note separates mature standards from moving targets and product signals.

---

## Reading Guide

- **Mature standard**: RFC, W3C Recommendation, or OpenID Final specification
- **Fast-moving standard**: formal specification work that is still evolving in practice
- **Official product signal**: a vendor product or documentation signal, useful but not normative
- **OSS / ecosystem signal**: evidence of real demand, but not a normative baseline

---

## 1. Official Standards and Building Blocks

| Layer | Current source / status | What already exists | Why this draft still matters |
|---|---|---|---|
| Agent discovery | A2A official docs under the Linux Foundation | Agent Cards publish identity, endpoint, authentication, and skills | Discovery does not fully define credential presentation, runtime proof, permit semantics, or receipts |
| Agent-to-tool authorization | MCP auth spec, OAuth 2.1-oriented | MCP clients and servers can negotiate authorization, and registry work is emerging | MCP is strong for tool access, but weaker for expressing who is calling on whose behalf under which mission permit |
| Portable credentials | W3C Verifiable Credentials Data Model v2.0 | issuer / holder / verifier relationships, presentation, consent, and schema-oriented validation | VC alone does not fully solve runtime proof, redelegation depth, or task-scoped permit semantics |
| Privacy-preserving credential status | W3C Bitstring Status List v1.0 | revocation and suspension lists can be distributed without leaking unnecessary identity information | Lists alone are not enough for incident push, quarantine, or continuous risk attenuation |
| Federation / trust anchor model | OpenID Federation 1.0 | multilateral trust relationships can be modeled via trust chains and trust anchors | Federation exists, but agent-specific credential, permit, and receipt semantics still need definition |
| Structured permission model | RFC 9396, RFC 8693, RFC 9449 | structured authorization, delegated token exchange, and proof-of-possession binding | this draft still needs to adapt these ideas to controller / principal / actor / runtime distinctions |
| Continuous attenuation | OpenID CAEP 1.0 | revoked sessions, changed claims, changed risk, and other events can be pushed | Useful foundation for the status signaling in this draft, but not specific to this repo on its own |
| Runtime / workload identity | SPIFFE / SPIRE and cloud workload identity systems | short-lived workload identity, attestation, trust domains, workload APIs | Helpful for runtime authenticity, but still incomplete for desktop agents, P2P agents, and cross-vendor portability |
| Cloud-native agent identity | Google Cloud Agent Identity | hosted agent runtimes can receive system-attested principals | Strong implementation signal, but still cloud-specific |

---

## 2. What the Standards Suggest

### A2A

- A2A frames the Agent Card as a discoverable description of agent identity, endpoint, authentication, and capability metadata.
- Discovery can happen through well-known locations, registries, or direct configuration.
- This suggests that **public discovery and trust decisioning remain separate concerns**.

### MCP

- MCP authorization aligns with OAuth-based patterns.
- Registry work strengthens the discovery and distribution side of tool integration.
- This suggests that MCP is strongest for **agent-to-tool** interaction, not for the full trust envelope around agent-to-agent or agent-to-service delegation.

### VC + Bitstring Status List

- VC provides a strong holder / issuer / verifier model.
- Bitstring Status List provides privacy-preserving publication of status.
- Together they are useful for the credentials and status references in this draft, but **runtime proof** and **mission permits** still need clearer treatment.

### OpenID Federation + CAEP

- OpenID Federation provides federation structure.
- CAEP provides a formal push-based model for risk and status changes.
- These are strong building blocks for the trust federation and status signaling in this draft.

### SPIFFE / Cloud Agent Identity

- Workload identity systems are strong at proving that a running workload is the workload it claims to be.
- Google Cloud Agent Identity is a particularly relevant example of a hosted agent runtime being treated as a first-class principal.
- These are natural anchors for runtime proof in this draft.

---

## 3. Official Product Signals

The following are not standards, but they do show where the ecosystem is moving.

| Signal | What exists now | Why it matters for this draft |
|---|---|---|
| Anthropic MCP product integration | MCP is integrated across Claude products and APIs | Tool-connected agents are already a product reality |
| OpenAI AgentKit / Connector Registry | connectors, MCP, approvals, and multi-agent workflows are productized | Admin, connector governance, and agent operations are becoming first-class product concerns |
| Microsoft A2A / MCP support | Microsoft has publicly supported open agent interoperability patterns | Vendor-neutral interoperability is gaining enterprise legitimacy |
| Salesforce Headless 360 (2026-04-15) | Salesforce capabilities are exposed as APIs, MCP tools, and CLI commands, with a new experience layer across surfaces | this draft should position itself as a portable trust layer that composes with those surfaces rather than as another platform UI or execution shell |
| Salesforce Agent Fabric expansion (2026-04-15) | discovery, deterministic orchestration, MCP Bridge, AI Gateway, and centralized LLM governance are framed as a trusted control plane | enterprise demand for governed multi-vendor control planes is real, but this draft should not expand its core into a control plane product |
| MuleSoft Trusted Agent Identity | authenticated user context is propagated with on-behalf-of delegation, gateway enforcement, and optional step-up verification | validates the delegated identity problem, while leaving room for the distinct runtime proof, mission permit, receipt, and status artifact model in this draft |
| Cloudflare Web Bot Auth | signed automated traffic can be verified at the web edge | Transport-level proof for automated callers is becoming practical |
| Visa Intelligent Commerce | payment rails are being adapted for agent-directed payment flows | Permit, instruction, and signal semantics matter in payment contexts |
| Visa CLI | command-line and MCP-compatible agent payment is surfacing as a real use case | agent commerce is no longer just a thought experiment |

---

## 4. OSS and Ecosystem Signals

| Project | Current shape | Why it matters |
|---|---|---|
| `agent-p2p` | encrypted P2P execution, Ed25519 identity, task/file transfer, escrow, trust scoring, skill matching | shows demand for execution rails, but still leaves room for portable trust / permit / receipt models |
| `Chisiki` | knowledge exchange, marketplace signals, reputation and insurance ideas | shows demand for portable admission and actor/runtime separation in knowledge-oriented agent ecosystems |

These projects are better understood as **adjacent complements** than as direct competitors to this draft.

- `agent-p2p` is closer to execution rail infrastructure
- `Chisiki` is closer to exchange and incentive design
- this draft is closer to trust, permission, and accountability semantics

---

## 5. Implications for v0.1

### What This Draft Should Standardize in the Core

1. controller / principal / actor / runtime distinctions
2. separation of credential, runtime proof, permit, receipt, and status
3. assurance levels and profile boundaries
4. task-scoped permit semantics, including redelegation depth
5. status and receipts as first-class protocol objects

### What This Draft Should Reuse

1. VC-like or JWT-like credential envelopes
2. structured authorization ideas from RAR
3. delegated exchange ideas from Token Exchange
4. proof-of-possession binding from DPoP or mTLS
5. federation ideas from OpenID Federation
6. status list ideas from Bitstring Status List
7. event-based attenuation ideas from CAEP / SSF
8. runtime authenticity ideas from SPIFFE, workload identity, and cloud attestation

### What This Draft Should Not Force Into the Core

1. a universal reputation score
2. a single global registry
3. a single issuer
4. a single blockchain
5. settlement or escrow protocol logic
6. mandatory KYC for all assurance levels

---

## 6. Recommended Repository Direction

To make this repository stronger as a globally legible protocol draft:

### Phase A: Spec Hygiene

- make English the primary outward-facing language
- separate standards from ecosystem signals
- add dates to time-sensitive references

### Phase B: Machine-Readable Artifacts

- publish JSON Schemas for the example artifacts
- keep examples and schemas in sync
- move toward validation and conformance-oriented test material

### Phase C: Community Readiness

- keep contribution rules simple and explicit
- separate core, profile, and extension discussion
- keep open questions concrete and reviewer-friendly

### Phase D: Conformance-Oriented Next Steps

- verifier-side checklists
- holder-side checklists
- A2A and MCP binding examples
- early AL2 / AL3 profile drafts

---

## 7. Practical Public Framing

The strongest framing for public release is:

- this draft is **not** a universal agent ID registry
- this draft is **not** a replacement for A2A or MCP
- this draft is a proposal for the missing **trust, permission, and accountability layer**
- this draft composes existing standards instead of discarding them
- this draft should stay small at the core and let profiles / extensions handle domain-specific concerns

That framing reduces the risk of the repo sounding grandiose while keeping the proposal legible to technical readers.

---

## 8. Source List

### Standards

- A2A Protocol: https://a2a-protocol.org/latest/
- A2A Agent Discovery: https://a2a-protocol.org/latest/topics/agent-discovery/
- MCP Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- MCP Registry: https://modelcontextprotocol.io/registry/about
- Verifiable Credentials Data Model v2.0: https://www.w3.org/TR/vc-data-model/
- Bitstring Status List v1.0: https://www.w3.org/TR/vc-bitstring-status-list/
- OpenID Federation 1.0: https://openid.net/specs/openid-federation-1_0.html
- OpenID Federation 1.0 Final Approval Note: https://openid.net/openid-federation-1-0-final-specification-approved/
- OpenID CAEP 1.0: https://openid.net/specs/openid-caep-1_0-final.html
- RFC 9449 (DPoP): https://datatracker.ietf.org/doc/html/rfc9449
- RFC 9396 (RAR): https://datatracker.ietf.org/doc/rfc9396/
- RFC 8693 (Token Exchange): https://www.rfc-editor.org/rfc/rfc8693
- SPIFFE: https://spiffe.io/

### Official product signals

- Anthropic MCP docs: https://docs.anthropic.com/en/docs/mcp
- OpenAI new tools for building agents: https://openai.com/index/new-tools-for-building-agents/
- OpenAI AgentKit: https://openai.com/index/introducing-agentkit/
- Microsoft Build 2025 A2A / MCP support: https://news.microsoft.com/source/asia/2025/05/20/microsoft-build-2025-the-age-of-ai-agents-and-building-the-open-agentic-web-en/
- Google Cloud Agent Identity: https://docs.cloud.google.com/agent-builder/agent-engine/agent-identity
- Salesforce Headless 360 announcement (2026-04-15): https://www.salesforce.com/news/stories/salesforce-headless-360-announcement/
- Salesforce Agent Fabric announcement (2026-04-15): https://www.salesforce.com/news/stories/agent-fabric-control-plane-announcement/
- MuleSoft Trusted Agent Identity: https://www.mulesoft.com/ai/trusted-agent-identity/announcement
- Cloudflare Web Bot Auth: https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/
- Visa Intelligent Commerce: https://developer.visa.com/capabilities/visa-intelligent-commerce
- Visa CLI: https://visacli.sh/

### OSS / ecosystem signals

- agent-p2p: https://github.com/satorisz9/agent-p2p
- Chisiki SDK: https://github.com/Chisiki1/chisiki-sdk
