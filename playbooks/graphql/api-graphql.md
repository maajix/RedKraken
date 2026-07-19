---
technique: "GraphQL"
family: "api"
severity_hint: "medium"
tags: []
source: "_raw/API/GraphQL.md"
source_sha256: "9d68bc89aee80ae1f1968096c15c9186692a6bd27669170a0ea9c42c9af00c38"
curator_version: 2
review_status: imported-unreviewed
---

# GraphQL

> Family: **api** · Severity hint: **medium** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `fragment+FullType+on+__Type+%7B++kind++name++description++fields(includeDeprecated%3a+true`
- `json: # SQLi`

## Playbook (operator notes)

# GraphQL

https://t.co/cyW7DYJaHS

- Check if Introspection is enabled
    - Should be disabled (*INFO*)
    - Check Querys and Mutations
    - Check If Mutations can called

```
fragment+FullType+on+__Type+%7B++kind++name++description++fields(includeDeprecated%3a+true)+%7B++++name++++description++++args+%7B++++++...InputValue++++%7D++++type+%7B++++++...TypeRef++++%7D++++isDeprecated++++deprecationReason++%7D++inputFields+%7B++++...InputValue++%7D++interfaces+%7B++++...TypeRef++%7D++enumValues(includeDeprecated%3a+true)+%7B++++name++++description++++isDeprecated++++deprecationReason++%7D++possibleTypes+%7B++++...TypeRef++%7D%7Dfragment+InputValue+on+__InputValue+%7B++name++description++type+%7B++++...TypeRef++%7D++defaultValue%7Dfragment+TypeRef+on+__Type+%7B++kind++name++ofType+%7B++++kind++++name++++ofType+%7B++++++kind++++++name++++++ofType+%7B++++++++kind++++++++name++++++++ofType+%7B++++++++++kind++++++++++name++++++++++ofType+%7B++++++++++++kind++++++++++++name++++++++++++ofType+%7B++++++++++++++kind++++++++++++++name++++++++++++++ofType+%7B++++++++++++++++kind++++++++++++++++name++++++++++++++%7D++++++++++++%7D++++++++++%7D++++++++%7D++++++%7D++++%7D++%7D%7Dquery+IntrospectionQuery+%7B++__schema+%7B++++queryType+%7B++++++name++++%7D++++mutationType+%7B++++++name++++%7D++++types+%7B++++++...FullType++++%7D++++directives+%7B++++++name++++++description++++++locations++++++args+%7B++++++++...InputValue++++++%7D++++%7D++%7D%7D
```

- Check for [Batching](https://lab.wallarm.com/graphql-batching-attack/) attacks
- Check for injection attacks

```json
# SQLi
query {
	user(id: “1'; SELECT * FROM users; — “) {
		id
		name
		email
	}
}

# Blind SQLi
query {
	user(id: “1 OR SLEEP(10)“) {
		id
		name
		email
	}
}

# Username enumeration
query {
	user(id: “1”) {
		id
		name
		email
	}
}

query {
	user(username: “john”) {
		id
		name
		email
	}
}
```

## HackTricks methodology enrichment

Use `../graphql/README.md` as the reviewed methodology. The
checks below add GraphQL-specific discovery and transport cases from HackTricks;
keep all fan-out and resource tests within the engagement's request budget.

### Discover and fingerprint the endpoint

1. Check common routes such as `/graphql`, `/graphiql`, `/api/graphql`, and
   `/graphql/console`, including routes found in JavaScript and API docs.
2. Send the low-cost universal query `query { __typename }` over each accepted
   transport: GET, form-encoded POST, and JSON POST. Record which combinations
   work because GET/form support can change the CSRF threat model.
3. Record the response shape, headers, error vocabulary, and exposed UI rather
   than treating introspection alone as proof of a vulnerability.
4. If authorized, fingerprint the engine with `graphw00f`; engine-specific
   follow-up belongs in a separate CVE lead and must be version-confirmed.

### Enumerate without assuming introspection

- Start with the smallest introspection query needed for the next step. If
  introspection is blocked, use field suggestions and validation errors to
  reconstruct one type or operation at a time.
- Search frontend bundles, mobile clients, docs, persisted-query manifests, and
  WebSocket frames for operation names, fragments, variables, and upload paths.
- Check whether newline/whitespace normalization, alternate transport, or a
  WebSocket subscription path applies a different introspection policy. A policy
  difference is a lead; demonstrate exposed data or authorization impact before
  calling it a finding.

### Authorization matrix

For every discovered query, mutation, subscription, nested resolver, and node
lookup, replay the same operation as unauthenticated, low-privilege owner,
low-privilege non-owner, and privileged users where the rules of engagement
provide those roles. Vary both the root identifier and nested object identifiers.
Also test aliases, fragments, global IDs, and mutation return fields because
authorization may be enforced at the root resolver but omitted in a nested one.

### Alternate execution paths

- Persisted queries and automatic persisted queries are an optimization, not an
  authorization boundary. Verify that both hash-only and full-query fallbacks
  enforce the same identity, operation allowlist, and variable rules.
- Test queries and mutations independently over HTTP and WebSocket transports.
  For cookie-authenticated WebSockets, validate `Origin`, CSRF/session binding,
  subscription ownership, and reauthorization after logout or role change.
- Multipart upload operations deserve the same file-policy and authorization
  checks as normal upload endpoints; keep files inert and below configured size
  limits.

### Bounded cost and rate-limit checks

Start with two aliases or two batched operations and increase one dimension at a
time while measuring status, latency, response size, and server error behavior.
Cover aliases, array batching, duplicated fields, directives, fragments, and
`@defer`/`@stream` only when supported. Stop on material latency, error-rate, or
resource impact. A valid result shows that the same logical action can exceed an
approved per-user limit or complexity policy—not merely that batching exists.

HackTricks source: [GraphQL](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html)
([snapshot reviewed](https://github.com/HackTricks-wiki/hacktricks/blob/d7dfcf8fa88bc49160a0fec341b16c763660ee4f/src/network-services-pentesting/pentesting-web/graphql.md)).

## Source
Original note: `_raw/API/GraphQL.md`
