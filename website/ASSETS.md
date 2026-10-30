# Golden Harbour assets and credits

This page follows the user-selected Golden Harbour concept. Scenery is artistic
illustration, not evidence of functioning infrastructure or measured positioning.
All headings, labels, controls, application marks, connections and uncertainty
rings are separate HTML/SVG elements. No visitor location is used.

## Shared identity and upstream marks

The exact reviewed shared source is
[homepage commit 8114d966](https://github.com/VOLPAROSSA/volparossa.github.io/commit/8114d966f3e9be878cb6dbb3d155a5739edfeb03),
theme v1.0.3. `theme/theme-version.json` identifies every imported file. The original
VOLPAROSSA logo remains unchanged in `theme/assets/logo-original.png`; the display
logo and favicon are the existing reviewed derivatives.

Cormorant Garamond and Inter are locally hosted WOFF2 fonts with their original
OFL notices. The GitHub mark is the official Octicon with its MIT notice in
`theme/assets/icons/`. Original site code follows the repository GPL-3.0-only
license. Shared project credits remain at <https://volparossa.org/credits/>.

OpenCode, Immich and OpenCloud SVGs are unchanged originals copied from the shared
export. Authoritative URLs, exact upstream revisions, hashes and mark conditions
are recorded in [the upstream registry](theme/notices/upstream-sources.json) and
[the retained asset register](theme/notices/ASSETS.md). Relevant OpenCode, Immich
and OpenCloud source notices remain in `theme/assets/upstream/` and are also copied
to the public artifact. Their names and marks identify the projects being built
upon; they do not imply partnership or endorsement. The user's choice to show
the marks is not a claim of third-party trademark permission. Set `upstream_marks`
to `false` in `config.json` for the maintained text-only variant. No external
party was contacted.

## Artwork

Six clean images were generated with `image_gen.imagegen` on 30 October 2026,
using the supplied selected reference as direction:

| Master | Composition | Separate overlay |
| --- | --- | --- |
| `artwork/masters/hero-desktop.png` | Sheltered dark quay, fox, workers, radiant harbour and cream sails | HTML title, actions and development badge |
| `artwork/masters/hero-mobile.png` | Intentionally recomposed portrait with the full fox and quay | HTML reading area above, soft CSS transition |
| `artwork/masters/shared-harbour.png` | Several equally important inhabited docks | Static decorative SVG connections, five native disclosures |
| `artwork/masters/intelligence.png` | People collaborating around a physical ship model | HTML content and development limits |
| `artwork/masters/dps.png` | Coastal navigation table, relief map and brass instrument | Fixed fictional SVG uncertainty rings and points |
| `artwork/masters/closing.png` | Welcoming harbour, ships and working quay | HTML invitation and participation explanation |

The exact prompts are in `artwork/prompts/`. `artwork/provenance.json` contains
master hashes, dimensions and the responsive export inventory. The original
user-supplied selected reference is retained in `artwork/reference.png` only for
maintenance, with its hash recorded there. The lossless masters and reference
are never copied into the site output or loaded by a visitor.

Responsive WebP images with JPEG fallbacks live in `assets/harbour/`. The mobile
hero is a separate composition. Other mobile scenes show the full image beneath
their text; wide desktop sections use documented CSS framing and soft paper
transitions. The five-layer connections are an artistic metaphor, not a transport
diagram or a central controlling hub. DPS is research using the five Core layers,
not a sixth layer or a live map. No motion is needed to understand either image.

`prepare_images.py` preserves masters, resizes with Lanczos, exports optimized
WebP/JPEG files and a 1200 × 630 hero social image. The original asset sources and
notices are retained; no browser-side generation or external asset service exists.
