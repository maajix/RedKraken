---
name: agentic-ai-attacks
description: Security testing for LLM and agentic web features, including indirect prompt injection, tool misuse, excessive agency, RAG poisoning, cross-tenant memory, insecure output handling, and MCP authorization or tool-poisoning failures.
---

# LLM, Agentic AI & MCP

Treat model output as probabilistic and require repeatable evidence. Use synthetic
canary data and test accounts; never ask a model to expose real secrets.

Start with `playbooks/modern/agentic-mcp-trust-boundaries.md`; it is the
source-reviewed safety and evidence contract for this family.

## Attack surfaces

- Direct and indirect prompt injection through user content, retrieved documents,
  images, URLs, tool results, source comments, and persisted memory.
- Tool misuse and excessive agency: unauthorized reads/writes, confused-deputy
  actions, unsafe argument construction, missing confirmation, or privilege reuse.
- RAG poisoning and cross-tenant retrieval, document access control, citation
  spoofing, and sensitive context leakage.
- Insecure model-output handling into HTML, SQL, shell, templates, redirects, or
  downstream agents.
- MCP: malicious tool descriptions, name collisions, token passthrough, incorrect
  token audience, protected-resource metadata confusion, SSRF through resources,
  elicitation abuse, sampling loops, and stream reconnection confusion.

## Confirmation

Use unique canaries to show the exact trust-boundary violation. Repeat trials and
record model/version, sampling settings, redacted transcript, tool-call arguments,
policy decision, and observed side effect. Persuasion without unauthorized data or
action remains suspected.
