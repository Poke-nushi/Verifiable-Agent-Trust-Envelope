# Standards and Ecosystem Landscape Update
## As of 2026-05-04

## Purpose

This note captures newer agentic web and commerce signals without expanding the VATE core.

The practical reading is:

- identity, discovery, request signing, and payment primitives are moving quickly
- VATE should compose with those primitives rather than replace them
- VATE's narrow contribution remains verifier-side admission, attenuation, policy versioning, and receipt / audit semantics

---

## Short Take

Recent ecosystem work strengthens the case for keeping VATE adjacent and verifier-centered:

- ANS-style naming can help an agent be discovered or resolved
- Web Bot Auth and signed-agent systems can authenticate automated HTTP requests
- Pay Per Crawl-style systems can express content access and payment expectations
- ACP and Stripe SPT can carry checkout and payment authorization
- A2A can carry task flow and references to verifier-side artifacts

None of those layers should be replaced by VATE.
VATE can sit after or beside them when a relying party still needs to decide whether a risky external action should be admitted, narrowed, denied, and later audited.

---

## Boundary Table

| Adjacent layer | Strongest at | VATE boundary |
|---|---|---|
| GoDaddy Agent Name Service (ANS) | human-readable and cryptographically resolvable agent naming / discovery | VATE should not be an agent name registry; it can consume resolved identity context as an input to verifier policy |
| Cloudflare Web Bot Auth / Signed Agents | signed automated web requests and verified agent traffic at the edge | VATE should not define the HTTP request signature system; it can model permit, status, admission decision, and receipt evidence around the request |
| Cloudflare Pay Per Crawl | content-owner access control and payment handling for crawler requests | VATE should not be a crawler payment rail; it can model whether a signed / paid content access request is admitted and what receipt should be retained |
| Agentic Commerce Protocol (ACP) | agentic checkout flow and delegated payment specification | VATE should not be a checkout protocol; it can record verifier-side admission for the risky action that precedes or accompanies payment execution |
| Stripe Shared Payment Tokens (SPT) | PSP-compatible delegated payment credential sharing | VATE should not tokenize payment credentials; it can reference payment authority as policy input and emit admission / post-execution receipts |
| A2A | discovery, messaging, and task delegation flow | VATE should not replace A2A; A2A metadata may reference VATE permits or receipts |
| MCP + OAuth | tool and resource authorization | VATE should not replace OAuth or MCP authorization; it can add actor / principal / runtime / permit / status context at verifier time |

---

## Example Compositions

### A2A task reference

An A2A task message can carry the task and compact references to verifier-side artifacts.
The v0.2 direction is to use the VATE extension URI as the metadata key and include digest-bound artifact references:

```json
{
  "metadata": {
    "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.2": {
      "profile": "VATE-AL2-Verifier-Admission-v0.2",
      "phase": "admission_issued",
      "transaction_id": "txn-20260504-001",
      "assurance_level": "AL2",
      "decision": "attenuate",
      "admission_receipt": {
        "type": "admission_receipt",
        "uri": "https://verifier.example/vate/admission-receipts/admrec-20260504-001",
        "media_type": "application/vate-admission-receipt+json",
        "digest": {
          "alg": "sha-256",
          "value": "base64url-admission-receipt-digest"
        }
      },
      "issuer": "did:web:verifier.example",
      "issued_at": "2026-05-04T03:00:08Z",
      "expires_at": "2026-05-04T03:10:08Z"
    }
  }
}
```

The full receipt body, attenuation details, and policy version remain in the verifier / receipt layer.

### Agentic checkout

An ACP / SPT-style checkout flow can continue to use its own payment and delegated credential primitives.
VATE can add a verifier-signed admission receipt before payment execution:

- decision: `allow`, `attenuate`, or `deny`
- policy_id and policy_version
- attenuations[] if amount, merchant, geography, or tool scope is narrowed
- post-execution receipt linked by `admission_receipt_ref`

### Signed crawler or content access

A Pay Per Crawl-style request can use existing crawler verification, request signature, and payment headers.
VATE can model the relying party's admission decision:

- which actor / runtime / permit was evaluated
- whether status narrowed the request
- which policy version allowed or denied access
- what receipt or audit evidence was retained

---

## Non-Goals Reaffirmed

VATE does not replace:

- ANS or other name / discovery systems
- Web Bot Auth or request-signature mechanisms
- Pay Per Crawl or crawler payment products
- ACP or Stripe SPT
- A2A
- MCP
- OAuth
- VC / JWT
- cloud workload identity

The v0.2 direction should therefore strengthen VATE as an adjacent verifier-side admission / permit / receipt layer, not broaden it into registry, commerce, transport, or identity infrastructure.

---

## Source List

- GoDaddy Agent Name Service: https://www.godaddy.com/resources/news/building-trust-at-internet-scale-godaddys-agent-name-service-registry-for-the-agentic-ai-marketplace/cover-1-11/
- Cloudflare Signed Agents: https://developers.cloudflare.com/bots/concepts/bot/signed-agents/
- Cloudflare Pay Per Crawl: https://developers.cloudflare.com/ai-crawl-control/features/pay-per-crawl/what-is-pay-per-crawl/
- Cloudflare Pay Per Crawl FAQ: https://developers.cloudflare.com/ai-crawl-control/features/pay-per-crawl/faq/
- ACP delegated payment specification: https://agentic-commerce-protocol.com/docs/commerce/specs/payment
- Stripe ACP documentation: https://docs.stripe.com/agentic-commerce/protocol
- Stripe agentic commerce announcement: https://stripe.com/blog/introducing-our-agentic-commerce-solutions
- A2A specification: https://a2a-protocol.org/latest/specification/
