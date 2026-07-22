# Script and scratch layout

Use the narrowest home that matches the helper:

- `scripts/`: reviewed, target-agnostic entry points reusable across every
  engagement. Network-capable helpers belong only here so the scope hook can
  inspect and trust a stable path.
- `lib/`: internal importable harness code; not an agent scratch area.
- `engagements/<name>/state/scripts/`: reusable helpers for one engagement.
  These may only transform local artifacts; they must not make target requests.
- `engagements/<name>/state/scratch/`: disposable notes and throwaway code.
- `engagements/<name>/state/scan-raw/`: raw scanner/capture output only.

Durable environment facts go in `state/notes.md`; tooling friction goes in
`state/harness-issues.md`; leads, findings, and coverage stay in their structured
state files. Do not use any script directory as a second scratchpad.

To promote an engagement helper into `scripts/`, remove target names, secrets,
and engagement-specific paths; use shared scope/config helpers; add one focused
test; then document its command here. Historical artifacts do not need migration.

## Shared network runner

Run hook-visible target HTTP tools as:

```bash
./scripts/run_scoped_http.sh curl https://in-scope.example/
```

The runner clears inherited proxy bypasses and sets all HTTP(S) proxy variants.
The actual tool and literal or inspectable-file targets must remain on the Bash
command line; never hide egress in a generated Python, Node, or shell driver.
