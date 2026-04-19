# Close Adjacent Work
## As of 2026-04-19

## Purpose

This note documents the public work most likely to be read as overlapping with this repository.

The goal is not to claim that this draft is the only work in the area.
The goal is to make the overlap legible early, so reviewers can argue about the actual protocol boundary rather than about whether prior art exists.

## Short Take

The closest public adjacent work today is:

- **Agent Permission Protocol (Crittora)** for explicit execution-time authorization
- **Open Agent Passport / APort** for passport + decision object + policy enforcement
- **Agent Passport System (APS / AEOESS)** for identity, delegation, governance, and receipts
- **AgentROA** for MCP-adjacent policy enforcement
- **Agent Auth / AIP drafts** for identity-first agent authentication work

This draft should be read as:

- narrower than APS
- less enforcement-product-shaped than AgentROA
- less permission-policy-centric than Crittora APP
- less passport-and-decision-object-centric than OAP
- broader than identity-only work because it includes runtime proof, permit, status, and receipt together

## Comparison Table

| Work | Strongest at | Where this draft is different |
|---|---|---|
| Crittora `Agent Permission Protocol (APP)` | explicit, time-bounded permission policy verified before execution | this draft centers on a composite artifact model across actor identity, runtime proof, permit, status, and receipt rather than a single permission policy plus enforcement gate |
| `Open Agent Passport (OAP)` / `APort` | passport object, decision object, and policy enforcement workflow | this draft is less productized and more focused on the verifier-side trust boundary across multiple artifacts |
| `Agent Passport System (APS)` / `AEOESS` | broad identity, delegation, governance, receipts, and commerce stack | this draft is much narrower and is not trying to define a full governance or commerce framework |
| `AgentROA` | policy enforcement for agent actions over MCP | this draft is transport-neutral and not specific to MCP route authorization |
| `Agent Auth Protocol` / `AIP` | authentication, trust bootstrap, and identity framing | this draft extends beyond identity into runtime proof, task-scoped permit, status, attenuation, and receipt semantics |

## 1. Crittora Agent Permission Protocol

### What is close

- execution-time authorization is explicit
- authority is scoped and time-bounded
- the verifier decision happens before the action executes

### What is different

Crittora APP is centered on a permission policy that gates execution.
This draft is centered on a composite trust envelope that lets a relying party reason across:

- actor identity
- principal linkage
- runtime proof
- task-scoped permit
- current status or attenuation
- receipt after execution

So the overlap is real, but the center of gravity is different.

Sources:

- <https://agentpermissionprotocol.com/>
- <https://www.crittora.com/static/agent-permission-protocol-whitepaper-bf15d5285450829cdfd6f2df55210ba9.pdf>

## 2. Open Agent Passport / APort

### What is close

- uses the passport metaphor
- includes policy enforcement and signed decision objects
- targets secure, verifiable interoperation

### What is different

OAP / APort is closer to an implementation-facing passport and decision workflow.
This draft is trying to stay narrower and more attackable as a protocol discussion draft:

- it keeps the focus on verifier-side admission for risky external actions
- it emphasizes runtime proof, status, and receipt semantics together
- it is not trying to define a `/verify` product surface as the main idea

Sources:

- <https://aport.io/spec/>
- <https://aport.io/spec/docs/DEVELOPER-GUIDE.md/>
- <https://aport.io/spec/docs/STANDARDS_COMPLIANCE.md/>

## 3. Agent Passport System

### What is close

- uses the passport framing
- includes scoped delegation and receipts
- treats governance and authority attenuation as explicit concerns

### What is different

APS is much broader.
It stretches into:

- governance
- coordination
- commerce
- multi-signature policy architecture

This draft is deliberately not doing that.
Its intended scope is smaller:

- a portable trust envelope for verifier-side trust and admission decisions
- a narrow `AL2` reference wedge
- profiles and extensions later, rather than a large governance stack up front

Sources:

- <https://www.ietf.org/archive/id/draft-pidlisnyi-aps-00.html>
- <https://aeoess.com/passport.html>

## 4. AgentROA

### What is close

- agent actions are evaluated against explicit authorization policy
- the relying party or enforcement point is central
- MCP-adjacent policy enforcement is explicit

### What is different

AgentROA is much closer to a route-authorization and MCP enforcement layer.
This draft is broader in transport but narrower in product shape:

- it is not tied to MCP
- it covers actor identity, runtime proof, permit, status, and receipt together
- it aims to remain transport-neutral across A2A, MCP, HTTP, and other surfaces

Source:

- <https://www.ietf.org/archive/id/draft-nivalto-agentroa-route-authorization-00.html>

## 5. Identity-First Work

Identity-centric work is also close, especially when it asks how agents authenticate and establish trust.
Examples include:

- Agent Auth Protocol
- AIP drafts

These validate the identity problem.
But this draft is not only about identity.
Its claim is that verifier-side decisions for risky external actions usually need more than identity alone:

- runtime proof
- task permit
- status / attenuation
- receipt

Sources:

- <https://agentauthprotocol.com/specification/v1.0-draft>
- <https://datatracker.ietf.org/doc/html/draft-aip-agent-identity-protocol-00>

## Practical Reading Rule

If a reviewer says:

- "this already exists as execution-time authorization"

the closest comparison is Crittora APP.

If a reviewer says:

- "this already exists as a passport and decision object"

the closest comparison is OAP / APort.

If a reviewer says:

- "this already exists as a broader governance stack"

the closest comparison is APS.

The useful next question is not "who used similar words first?"
It is:

- is the boundary in this repo still worth discussing as its own draft
- and if so, is that boundary currently drawn in the right place

## Review Questions

The most useful critique for this note is:

- is the distinction from Crittora APP stated clearly enough
- is the difference from OAP / APS concrete enough
- is this draft still too broad even after that comparison
- which parts should move into profiles or examples rather than stay in the core
