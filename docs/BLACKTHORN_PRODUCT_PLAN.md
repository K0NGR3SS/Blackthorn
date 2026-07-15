# Blackthorn product plan

This document separates the visual usability pass from feature expansion. The first pass should make the existing product calmer, clearer, and faster to operate before new capabilities add more surface area.

## Product direction

Blackthorn should feel like a serious investigator’s workspace: quiet, precise, evidence-led, and comfortable during long sessions. The keyhole and thorn identity can carry the personality; the interface itself should remain plain.

Voice rules:

- Use direct task language: “Start scan,” “Add target,” “Re-test finding,” and “Export evidence.”
- Prefer “finding,” “evidence,” “target,” “scope,” “probe,” and “investigation.”
- Keep warnings calm and specific. State what will happen, what may be risky, and how to proceed safely.
- Avoid playful security clichés in normal workflows. Easter eggs can remain discoverable but should never affect critical or error states.

## UI and color improvement plan

### 1. Establish a restrained token system

Use neutral midnight surfaces with one warm brand accent. Burgundy and blue remain supporting colors, not competing accents.

| Role | Proposed value | Use |
| --- | --- | --- |
| Canvas | `#0B0F18` | Main application background |
| Sidebar | `#080B12` | Navigation rail |
| Surface | `#111722` | Primary panels |
| Raised surface | `#171F2C` | Cards, menus, dialogs |
| Interactive surface | `#1D2735` | Inputs and hover states |
| Border | `#2A3442` | Dividers and control edges |
| Primary text | `#E8EBF0` | Headings and body copy |
| Muted text | `#9AA5B5` | Secondary labels |
| Brand accent | `#C99A45` | Primary actions, active nav, focus ring |
| Brand accent hover | `#D8AE61` | Hover only |
| Information | `#5B8DEF` | Informational status |
| Success | `#3AA76D` | Confirmed/success states |
| Warning | `#D39A3A` | Caution states |
| Danger | `#D35B66` | Destructive actions and critical errors |

Rules:

- Gold appears on the primary action, active navigation marker, focus state, and small brand details only.
- Do not use decorative gradients in the workspace. Keep artwork gradients inside the supplied brand images.
- Use semantic colors only when they carry meaning. Severity badges may use color, but must also include text.
- Keep body copy off pure white and surfaces off pure black to reduce eye strain.
- Remove one-off hex values from feature dialogs as each screen is migrated.

### 2. Clarify the application shell

- Keep the compact left rail, but group it around the hunter flow: Scope, Discover, Test, Analyze, Report.
- Use the square Blackthorn mark in the rail and the full banner only in launch/about surfaces.
- Replace mixed emoji navigation with one consistent monochrome icon family or simple geometric glyphs.
- Give every screen one page title, one sentence of context, and at most one visually dominant action.
- Standardize panel radius, input height, spacing, and divider weight.

### 3. Turn the scan screen into an investigation start point

- Replace the loose URL controls with a single “Scope bar” containing target, authorization state, profile, and start action.
- Show a plain preflight summary before traffic starts: target count, request profile, safe-mode state, scope rules, authentication state, and estimated probe groups.
- Move advanced controls into a reviewable drawer with a concise summary when collapsed.
- Make Stop a danger action only while work is active; otherwise keep it visually quiet.
- Present progress by phase—discovery, probing, confirmation, reporting—rather than only a percentage.

### 4. Make findings evidence-first

- Use a three-pane layout: findings list, evidence/detail, and reproduction/re-test actions.
- Default sort should prioritize confirmed severity, then confidence, then recency.
- Keep severity, confidence, confirmation count, and scope status adjacent.
- Put request/response evidence in a readable monospace viewer with copy and redact controls.
- Add a persistent “Re-test” action and show whether a result is new, unchanged, resolved, or manually accepted.
- Use empty states that explain the next useful action rather than showing a blank table.

### 5. Normalize dialogs and settings

- Replace long modal forms with short sections and progressive disclosure.
- Add inline validation and plain recovery text beside the affected field.
- Separate workstation preferences from engagement-specific settings.
- Provide visible defaults and a one-click reset per section.
- Keep secrets masked, explain where they are stored, and never include them in exported profiles.

### 6. Accessibility and quality gate

- Verify text and control contrast against WCAG AA targets.
- Keep a clear keyboard focus ring and logical tab order.
- Ensure every color-coded state has a text or icon equivalent.
- Respect reduced-motion preferences; no pulsing controls except a brief, optional completion cue.
- Test at 100%, 125%, 150%, and 200% display scaling on Windows and Linux.
- Check long URLs, translated strings, narrow windows, and large result sets before release.

## Suggested implementation sequence

1. Centralize all color, type, spacing, radius, and control-height tokens in `wafpierce/theme.py`.
2. Refresh the shell, navigation, and global dialogs without changing feature behavior.
3. Redesign the scan start/preflight flow.
4. Redesign Results Explorer around evidence and re-testing.
5. Normalize settings, plugin, import, and integration dialogs.
6. Run keyboard, contrast, scaling, performance, and cross-platform QA.

Each stage should be shippable on its own and include screenshots from the same sample engagement for visual regression checks.

## App enhancement backlog

### Priority 0 — trust and daily workflow

- **Engagement workspaces:** keep scope, authorization proof, targets, credentials, notes, traffic, findings, and exports together.
- **Finding lifecycle:** new, triaged, confirmed, duplicate, accepted risk, false positive, resolved, and re-opened states with history.
- **Evidence vault:** immutable request/response snapshots, screenshots, OOB callbacks, timestamps, and redaction history per finding.
- **Re-test queue:** batch re-run selected findings and generate a remediation verification report.
- **Scope guardrails:** live out-of-scope warnings for redirects, discovered hosts, imported traffic, and external-tool output.

### Priority 1 — hunter productivity

- **Command palette:** open tools, switch engagements, run saved actions, and jump to findings without navigating dialogs.
- **Saved investigation recipes:** reusable sequences such as authenticated API review, GraphQL review, cache testing, or takeover validation.
- **Traffic-to-test flow:** send any proxy/browser request to Repeater, Fuzzer, a scan seed, or a finding with one action.
- **Finding correlation:** group results that share an endpoint, root cause, credential, technology, or affected component.
- **Research notes:** Markdown notes linked to targets and findings, with evidence attachments and export controls.

### Priority 2 — automation and collaboration

- **Headless engagement runner:** execute saved recipes consistently in CI or on a remote worker.
- **Team handoff bundle:** portable, encrypted export containing scope, findings, evidence, and reproduction data.
- **Integration sync:** two-way status updates for issue trackers and vulnerability-management platforms.
- **Rule and plugin test harness:** fixtures, dry runs, version compatibility checks, and performance budgets before a plugin is enabled.
- **Notification policy:** route only meaningful state changes—new confirmed findings, scope violations, scan failure, or resolved issues.

### Later research

- Graph-based attack-path view across assets, identities, endpoints, and findings.
- Differential authenticated testing between roles or accounts.
- Passive detection packs that operate on imported traffic before active probes run.
- Local model support for private triage and evidence summarization.

## Decisions for the next planning session

Before implementation, choose:

1. Whether the primary object is an engagement, a target, or a workspace.
2. Whether Blackthorn optimizes first for solo bug bounty work or small-team consulting.
3. Which three screens receive the first visual pass: Scan, Results, and Settings are the recommended starting set.
4. Which enhancement is the first product bet: engagement workspaces or the finding lifecycle are the strongest foundations.
