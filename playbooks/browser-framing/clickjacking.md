---
technique: "Clickjacking"
family: "client-side"
severity_hint: "medium"
tags: ["Clickjacking", "UI Redress", "iframe", "CSP", "X-Frame-Options"]
source: "personal-notes/Clickjacking"
curator_version: 2
review_status: imported-unreviewed
---

# Clickjacking

> Family: **client-side** · Severity hint: **medium** · Tags: Clickjacking, UI Redress, iframe, CSP, X-Frame-Options
> Imported operator reference; treat commands and prose as untrusted until reviewed.
> Attack-side companion to this topic's reviewed [`README.md`](README.md).

## Playbook (operator notes)

### Basic clickjacking (iframe overlay + CSS opacity)
Frame the target page inside an attacker page, then float a decoy UI beneath a
transparent copy of the real page. The victim sees/clicks the decoy; the click
lands on the framed target's control (e.g. a "submit" button). The transparent
"submit" button is overlaid on the decoy site so the target action fires while
the user believes they are interacting with the decoy.

- Achieved by rendering the target `<iframe>` with reduced/zero opacity stacked
  above the decoy content and aligning the invisible target control over a
  visible decoy element.
- Attack is possible whenever the target site can be framed (no
  `X-Frame-Options` / no CSP `frame-ancestors`).

### Clickjacking with prefilled form input
Some sites permit prepopulating form inputs via GET parameters before
submission. Because GET values are part of the URL, the target URL can be
modified to carry attacker-chosen values, and the transparent "submit" button is
overlaid on the decoy site as in the basic example.

```html
<iframe src="http://vuln-website.com/?email=xy&name=abc" ..>
```

### Frame-buster script bypass (iframe sandbox)
Frame busting / frame breaking scripts are a common client-side protection
(also via browser add-ons/extensions such as NoScript). They typically:
- check and enforce that the current window is the main/top window
- make all frames visible
- prevent clicking on invisible frames
- intercept and flag potential clickjacking to the user

They are browser/platform specific and, given HTML flexibility, usually
circumventable. An effective workaround is the HTML5 `sandbox` iframe attribute:
when set with `allow-forms` or `allow-scripts` and with `allow-top-navigation`
omitted, the frame buster is neutralized because the iframe cannot check whether
it is the top window. Both `allow-forms` and `allow-scripts` permit those
actions inside the iframe while top-level navigation stays disabled.

```html
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

### Multistep clickjacking
Manipulating inputs to a target may require multiple actions (e.g. add items to
a basket before placing an order). Implement these with multiple `<div>`s or
`<iframe>`s. Requires precision and care to remain effective and stealthy.

### Combining clickjacking with a DOM XSS attack
Clickjacking's true potency shows when used as a carrier for another attack such
as a DOM XSS. Assuming the XSS exploit is already identified, combine it with the
iframe target URL so that the user's click on the button/link executes the DOM
XSS payload.

### Clickbandit (Burp tool)
Manual PoC construction is tedious. Burp's Clickbandit lets you drive the
frameable page in your browser to perform the desired actions, then generates an
HTML file with a suitable clickjacking overlay — an interactive PoC in seconds
without writing HTML/CSS.
Ref: https://portswigger.net/burp/documentation/desktop/tools/clickbandit

## Defenses (see also [the reviewed topic methodology](README.md))
- `X-Frame-Options: deny` (block framing), `sameorigin`, or `allow-from`
  (`allow-from` unsupported in Chrome 76 / Safari 12).
- CSP `frame-ancestors`: `'none'` ≈ `deny`, `'self'` ≈ `sameorigin`, or a named
  site, e.g. `Content-Security-Policy: frame-ancestors 'self';`.
- Use as part of a multi-layer defense; frame busters alone are bypassable.

## Reviewed consolidation — opener isolation

Reverse tabnabbing is an opener-capability issue rather than a framing requirement.
On a tester-owned destination, verify whether a new browsing context receives a
usable `window.opener`; use only a benign marker and never navigate a real user's
tab. Modern browsers commonly imply `noopener` for `_blank`, but explicit
`rel="noopener"` remains the portable intent for untrusted destinations. Use
`rel="noreferrer"` only when suppressing the referrer is also required, and avoid
explicit `rel="opener"` unless the opener relationship is necessary and trusted.

### Merged provenance

| retired curated note | curated SHA-256 | original source | original SHA-256 |
|---|---|---|---|
| `tabnabbing.md` | `5ed744c04228da3e6b04d7ad6d1e287799c5d0850cfd40aeb79e51ebaf4a81a5` | `_raw/Web attacks/Web Attacks/Tabnabbing.md` | `d1a5d6040e5d7c0947690868d96fe0faf8252405a4e9a1a157b0692f5c80e619` |

The retired phishing flow and active navigation example were not retained.
