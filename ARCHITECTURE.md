# Architecture

```
launch command ──> client.py ──> Manifest ──┬──> rules/*      ──┐
  (or --manifest file)                      └──> lockfile.diff ─┴──> [Finding] ──> report.py
```

Everything flows through two types: a `Manifest` (what the server advertises) and a list of
`Finding`s (what is wrong with it). Nothing downstream of `client.py` knows a server process
ever existed, which is why `--manifest tools.json` works and why rules are trivial to test.

## Modules

| File | Job |
| --- | --- |
| `client.py` | Minimal stdio MCP client: spawn the server, `initialize`, page through `tools/list`. Reader threads feed a queue so requests can time out on Windows, where pipes cannot be polled. |
| `manifest.py` | `Manifest` and `Tool`. Knows how to walk a JSON Schema for every model-visible string (`text_fields`) and every parameter (`parameters`), and how to hash a tool canonically. |
| `rules/base.py` | `Severity`, `Finding`, the rule registry, and the helpers every rule uses: `texts()` to iterate model-visible strings, `visible()` / `ident()` to print hostile text safely. |
| `rules/*.py` | One module per rule family. Each exposes `check(manifest) -> Iterator[Finding]`. |
| `lockfile.py` | Build, write, load and diff `.gauntlet.lock`. Drift is reported as ordinary findings. |
| `report.py` | Terminal report card and JSON. |
| `cli.py` | Argument parsing and exit codes. |
| `demo/trapdoor.py` | The bundled malicious server. Also the fixture the end-to-end tests run against. |

## Adding a rule

1. Declare it in the module for its family:

   ```python
   SHOUTING = rule(
       "GA-I010",
       Severity.LOW,
       "Description is mostly capitals",
       "Use sentence case. All-caps text is a cheap way to add weight to an instruction.",
   )
   ```

2. Yield it from that module's `check()`:

   ```python
   for tool, location, text in texts(manifest):
       if len(text) > 40 and sum(c.isupper() for c in text) > len(text) / 2:
           yield SHOUTING.hit(tool, location, f'"{excerpt(text, 0, 60)}"')
   ```

3. Add a positive case and a benign case to `tests/test_rules.py`. The benign list matters as much
   as the poisoned one: a scanner that cries wolf gets switched off.

`rule()` registers the rule, so it appears in `gauntlet rules` with no further wiring.

## Decisions worth knowing about

**No dependencies.** The MCP SDK would have saved a hundred lines and cost a dependency tree. For a
tool whose pitch is "audit what you install", the hundred lines are the better trade.

**Evidence is always escaped.** Findings quote text written by a potential attacker and print it to
a terminal. Every quoted string goes through `visible()` or `ident()`, so invisible characters,
bidi overrides and look-alike letters are shown as `<U+XXXX>` rather than rendered.

**Hidden text is linted, not just detected.** `texts()` decodes tag-character payloads and yields
them as a second field, so the content rules read what the model reads.

**The grade is the worst finding, not an average.** One poisoned tool in a server of fifty clean
ones is still a server that can take over your agent.

**The lockfile stores descriptions in clear.** Hashes alone say *that* something changed. With the
text in the file, `git diff` on the lockfile says *what* changed, in the place reviewers already look.

**Only manifest-contract fields are hashed.** `name`, `title`, `description`, `inputSchema`,
`outputSchema`, `annotations`. Extra keys a server adds (`_meta` and friends) do not trip the
drift check.
