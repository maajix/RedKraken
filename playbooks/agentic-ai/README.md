---
id: modern-agentic-mcp-trust-boundaries
title: Agentic AI and MCP Trust Boundaries
family: agentic-ai
review_status: source-reviewed
reviewed_at: 2026-07-10
destructive_risk: high
---

# Agentic AI and MCP Trust Boundaries

## Threat model

Map untrusted instructions from user prompts, retrieved documents, web pages,
images, memory, tool results, MCP metadata, and peer agents to model decisions,
tool calls, credentials, network access, and side effects. A convincing model
response is not impact; the boundary violation must be observable.

## Safe detection

1. Use unique synthetic canaries and dedicated test tenants. Record model/version,
   system policy version, tools/scopes, sampling settings, and memory state.
2. Place a benign instruction canary in each untrusted channel separately and
   observe whether it changes tool selection, arguments, data access, or output.
3. Test excessive agency with reversible actions: missing approval, overly broad
   tool scopes, credential reuse, unsafe argument construction, and confused
   deputy behavior. Do not request real secrets or destructive actions.
4. Test RAG tenant/object authorization, poisoning persistence, citation/source
   integrity, memory isolation, and insecure model output reaching HTML, SQL,
   shell, templates, redirects, or downstream agents.
5. For MCP, test token audience/resource binding and prohibit token passthrough;
   metadata-discovery SSRF/redirect/DNS-rebinding defenses; session ownership;
   tool-name/description collisions; local-server authorization; and least scope.
6. Repeat probabilistic trials with negative controls. Stop after a minimal,
   reversible unauthorized read or action on synthetic data.

## Confirmation and evidence

Save redacted transcripts, canary placement, tool-call arguments, policy/approval
decisions, side effect, cleanup, and trial counts. Prompt obedience without an
unauthorized disclosure or action remains suspected.

## Remediation

Treat all model inputs and tool metadata as data, separate planning from policy
enforcement, authorize tools and objects outside the model, minimize scopes,
require confirmation for consequential actions, sandbox local servers, validate
MCP token audience/resource, block token passthrough, and constrain discovery
egress against SSRF and DNS rebinding.

<!-- BEGIN GENERATED TOPIC REFERENCES -->
## Imported operator references

These sibling notes provide payload and command depth. They remain
`imported-unreviewed`; validate commands and prose before use.

- [LLM](llm.md) — severity hint: medium
<!-- END GENERATED TOPIC REFERENCES -->

## Sources
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
