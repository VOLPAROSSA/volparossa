# Compute and satellite correction — 30 October 2026

Replaces the malformed custom Compute gear and Multiple sources satellite with
Lucide’s original settings and satellite SVG geometry, pinned at
`a630cec77eac6568b989e87e4947a8bfe45caacd`. Original files and full notices remain
under `assets/icons/lucide/`; their Git blob hashes match the source. Only the
outer SVG attributes change during inlining, preserving existing decorative
semantics, dimensions, copper colour and line weight.

Preview and production builds and offline checks pass. Actual Chromium and
Firefox renders at 390 and 1440 CSS pixels confirm both shapes fit their viewBox
without clipping; page reflow and decorative accessibility remain intact. Both
desktop and mobile renders were visually inspected. No CSS, text, page artwork,
carousel behavior, shared theme, runtime or deployment configuration changes.
The broader exact-source interaction and performance results from PR364 remain
applicable to their unchanged inputs; no new runtime or broad performance trial.

- [Desktop gear](review/icons/firefox-compute-1440.png) and [satellite](review/icons/firefox-satellite-1440.png)
- [Mobile gear](review/icons/firefox-compute-390.png) and [satellite](review/icons/firefox-satellite-390.png)
- [Browser geometry results](review/icons/results.json)

Publication follows the existing protected PR and Pages workflow. The PR records
required checks and the final live verification after deployment.
