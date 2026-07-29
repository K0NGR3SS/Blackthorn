# Payload Workbench improvement plan

## Outcome

Turn the current flat custom-payload list into a practical, explainable
workbench for authorized bug-bounty and CTF testing. A tester should be able to
answer all of these before a request leaves Blackthorn:

1. What technique and variant did I choose?
2. What signal should I look for?
3. Which exact URL, parameter, property, header, cookie, path, or body receives it?
4. What encoding will the application receive?
5. What exact request will Repeater or Intruder send?

The workbench must remain useful without a database: built-ins are always
available, while saved/imported payloads are an optional local layer.

Implementation status: Phases 1–3 are complete on the working branch. Each
phase is preserved as a separate local commit.

## Current friction

- The Payload library is a flat list of saved values, so it does not help a
  tester discover an appropriate technique.
- SQL injection, XSS, command injection, and other variants are mixed into
  separate hard-coded sets in Intruder.
- There is no distinction between SQL syntax, boolean, authentication-bypass,
  UNION, error-based, and time-based probes.
- The UI does not identify an insertion point or show the final encoded request.
- A payload cannot be handed to Repeater or a whole family handed to Intruder
  from the library.
- Descriptions do not state an expected signal, platform, or testing impact.

## Category improvements

| Category | Navigation and variants | Handy workflow guidance |
| --- | --- | --- |
| SQL injection | Syntax probes; paired boolean/basic `1=1`; authentication bypass; UNION preparation; UNION SELECT; error based; time based; MySQL, PostgreSQL, and SQL Server labels | Start with low-impact syntax and paired true/false controls. Show column-count and DBMS assumptions before UNION/time probes. |
| Cross-site scripting | HTML body, attribute, JavaScript string, and URL contexts | Match a payload to the reflection context, state the expected browser signal, and use an isolated verification profile. |
| Command injection | Unix separators, substitution, bounded timing, and Windows separators | Favor `id`, `whoami`, and short sleeps; label these as moderate impact and avoid state-changing commands. |
| Path traversal / LFI | Linux, Windows, separator normalization, and double encoding | Use predictable non-secret files and show the final path after encoding. |
| SSRF | Loopback, alternate IP representation, controlled callback, and metadata root | Prefer callback hosts the tester controls. Clearly label metadata access and stop before credential paths. |
| XXE | Inline entity, XInclude, and controlled callback | Compose a complete XML body, preserve its content type, and avoid entity-expansion denial-of-service payloads. |
| SSTI | Jinja/Twig, FreeMarker/EL, and ERB fingerprint families | Start with arithmetic/string evaluation markers; do not bundle code-execution payloads into the starter catalog. |
| NoSQL injection | Raw Mongo-style operator bodies and operator-shaped properties | Keep raw JSON bodies valid and compare against an impossible/control query before interpreting auth changes. |
| Encoding / filter normalization | Case, SQL comments, whitespace, and browser-parser variation | Always compare a canonical and transformed pair; only flag a filter difference when application semantics remain equivalent. |
| Custom | Saved and imported local entries mixed into the same search/filter model | Preserve source labels and require the tester to choose an insertion point and expected signal. |

## Implementation phases

### Phase 1 — Shared catalog and exact request model

- Add a Qt-free catalog with categories, families, payloads, descriptions,
  expected signals, platforms, compatible insertion points, and impact labels.
- Add explicit encodings and request placement for query, path, form, JSON,
  header, cookie, and raw body.
- Preserve existing parameters/fields and render exact HTTP and cURL previews.
- Adapt existing database rows into the same catalog without a schema migration.
- Generate Intruder sets from the same source of truth.

Acceptance:

- SQL injection exposes boolean/basic `1=1`, auth, UNION, error, time, and DBMS
  choices.
- Every built-in has an expected signal and compatible insertion point.
- Unit tests cover filtering, all placement types, encoding, preview, cURL, and
  Repeater handoff.

### Phase 2 — Payload Workbench interface

- Replace the flat list with category, family, impact, source, and text filters.
- Show details and an editable payload beside the library.
- Add a request composer with method, target, insertion location/name, encoding,
  headers, and base body.
- Keep a persistent destination summary and exact request preview visible.
- Add Copy payload, Copy cURL, and Open in Repeater actions.
- Move saved/imported/deleted custom payloads into a dedicated tab.

Acceptance:

- A new tester can select “SQL injection → UNION SELECT” without scanning a
  mixed payload list.
- Changing location or encoding immediately updates the destination and request.
- Repeater receives exactly the request shown in the preview.
- Built-ins still work if the custom-payload database is unavailable.

### Phase 3 — Family testing and workflow integration

- Replace Repeater/Intruder’s duplicate hard-coded sets with the shared catalog.
- Add “Test family in Intruder,” using a previewed `FUZZ` insertion point and the
  selected family only.
- Preserve custom-family support and show the handoff status.
- Add offscreen UI regression tests and update user-facing documentation.

Acceptance:

- Payload Library and Intruder cannot drift into different built-in sets.
- Family handoff preserves the selected method, target, headers, body, and
  insertion point.
- No request is sent directly from the library; Repeater/Intruder remain the
  deliberate send boundary.

## Safety and scope

Blackthorn should keep the legal authorization gate and make the workbench’s
boundary explicit: composing/copying is local, while Repeater or Intruder sends
network traffic. The starter catalog excludes destructive commands, persistence,
credential theft, and resource-exhaustion payloads. Moderate-impact probes are
visibly labelled so program rules can be checked before use.
