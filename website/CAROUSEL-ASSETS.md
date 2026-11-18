# Application carousel: sources and behavior

The user requested every application except Bank and Citizen. The existing pinned
shared application registry supplies the nine names, upstream names, development
status and publication destinations: Code, Image, Cloud, Browser, Chat, Mail, Map,
Weather and Studio. This matches the application scope in
[`docs/development/GOAL.md`](../docs/development/GOAL.md). Unpublished projects link
to their repositories, visibly labelled as such. The carousel changes no product
implementation or maturity claim.

## Original icons

All icons are unchanged bytes from their original sources, hosted locally. They
identify the upstream projects named beside them, without claiming endorsement.
No icon was generated or redrawn. The maintenance register
[`assets/apps/sources.json`](assets/apps/sources.json) records exact download URLs,
revision pins where available, SHA-256 hashes, byte lengths and retrieval date.

| Application | Original identifying asset | Source and retained notice |
| --- | --- | --- |
| Code | OpenCode | Existing pinned shared theme, `theme/assets/upstream/` |
| Image | Immich | Existing pinned shared theme, `theme/assets/upstream/` |
| Cloud | OpenCloud app icon | Official documentation revision `63b6a88d6570189212e91c5733940ff54fbade82`; original `OPENCLOUD-LICENSE.txt` |
| Browser | Firefox Browser icon | Firefox official website; Mozilla trademark terms below |
| Chat | Signal | Signal Desktop source revision `5dad34ad5ea1a5b6229412e5c8ac0a696ff7532d`; original `SIGNAL-LICENSE.txt` |
| Mail | Thunderbird | Thunderbird official website; Mozilla/MZLA trademark terms below |
| Map | Organic Maps launcher icon | Integration-pinned revision `b20d1417eef1e3c63a447ac8658db4307a066024`; original Apache license and `NOTICE` |
| Weather | Drizz.li and Overmorrow icons | Both integration-pinned sources: `d2a6839e2b3f2e561b849d83014fc5959bed39cc` and `97995e2e00e454389e00e35f1e65654afe3e8bed`; both original licenses |
| Studio | Silex pictogram by Ceubri | Integration-pinned revision `672efed69dda04c0a1e968859239e042f00d9538`; original `SILEX-LICENSE.txt` |

Source licenses are preserved unchanged; they do not convey trademark rights.
Firefox and Thunderbird marks retain their original branding:
<https://www.mozilla.org/en-US/foundation/trademarks/policy/> and
<https://www.thunderbird.net/en-US/thunderbird/trademarks/>.
All marks can be disabled through the existing `upstream_marks` configuration.
No third party was contacted.

## Interaction

`applications.py` renders the entire nine-project list into HTML. Without JavaScript,
all nine cards and their links remain in an ordinary responsive grid. With the
local `carousel.js` enhancement, the strip shows three cards on desktop, two on
intermediate widths and one on mobile, advancing every six seconds. The next and
previous controls wrap through all projects, and touch visitors can swipe.

A visible pause/start control is first in keyboard order. Rotation pauses while
hovered, while any carousel control or card has keyboard focus, outside the
viewport and while the browser document is hidden. Reduced-motion visitors start
with rotation off and no sliding transition. Moving the focus never triggers a
slide change. Offscreen cards are inert and hidden from the accessibility tree;
manual changes are politely announced. No clones, remote requests, dependencies,
stored preferences or tracking are involved.

`carousel_check.mjs` exercises all nine projects, icons, navigation/wrapping,
automatic movement, focus/hover/offscreen pausing, explicit pause/start,
reduced motion, responsive layout and the no-JavaScript fallback in Chromium and
Firefox. Run against the local preview with the same pinned Playwright dependency
as `browser_check.mjs`.
