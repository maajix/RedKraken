---
technique: "DTD\u2019s"
family: "ssrf-xxe-file"
severity_hint: "critical"
tags: []
source: "_raw/Web attacks/Web Attacks/XXE/DTD\u2019s.md"
source_sha256: "c35c1c560a9b2e88ce65342dad6616916eac9315e96873796353a38b77e20533"
curator_version: 2
review_status: imported-unreviewed
---

# DTD’s

> Family: **ssrf-xxe-file** · Severity hint: **critical** · Tags: —
> Imported operator reference; treat commands and prose as untrusted until reviewed. Tools seen: —.

## Quick index — payloads & commands in this note
- `xml: <!DOCTYPE people [`

## Playbook (operator notes)

# DTD’s

A DTD is a set of **rules** that defines the structure of an XML document. Just like a database scheme, it acts like a blueprint, telling you what elements (tags) and attributes are allowed in the XML file. Think of it as a guideline that ensures the XML document follows a specific structure

For example, if we want to ensure that an XML document about **`people`** will always include a **`name`**, **`address`**, **`email`**, and **`phone number`**, we would define those rules through a DTD as shown below

```xml
<!DOCTYPE people [
   <!ELEMENT people(name, address, email, phone)>
   <!ELEMENT name (#PCDATA)>
   <!ELEMENT address (#PCDATA)>
   <!ELEMENT email (#PCDATA)>
   <!ELEMENT phone (#PCDATA)>
]>
```

In the above DTD, **<!ELEMENT>**  defines the elements (tags) that are allowed, like name, address, email, and phone, whereas **`#PCDATA`** stands for parsed **`people`** data, meaning it will consist of just plain text.

## Source
Original note: `_raw/Web attacks/Web Attacks/XXE/DTD’s.md`
