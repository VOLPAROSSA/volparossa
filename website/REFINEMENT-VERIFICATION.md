# Core concept refinement and carousel — 30 October 2026

The owner’s review requested closer matching of every scene below the hero and an
automatic carousel of all applications except Bank and Citizen. This revision is
based on published Core commit `10836b7416ce7e09cec64c80353268997032336b`.

## Visual result

Four clean scene masters were reconstructed directly from the selected concept:
the wide multi-dock panorama, collaborative workshop with a golden wireframe ship,
DPS chart table with brass instrument and navigator, and closing quay with a large
cream-sailed ship. Desktop artwork retains its scene proportions; paper fades
preserve readable text. Mobile shows the scenes after their text; the workshop
frames the people and model. The panorama’s SVG connections align with the new
docks. DPS’s fixed artistic rings are part of its scene, without a duplicate SVG.
All visible text, controls and app icons remain separate HTML/SVG.

The 19 hero master/export/social files are byte-for-byte identical to the base.
The shared theme and homepage source were not changed. Revised scenery URLs include
a master hash to avoid stale browser assets. Prompts, masters, hashes, original
upstream icons and unchanged notices are retained in the source.

Actual Chromium and Firefox renders were reviewed against the selected concept,
including all three desktop carousel groups and the mobile page:

- [Desktop](review/refinement/firefox-1440.webp) · [Mobile](review/refinement/firefox-390.webp)
- [Workshop](review/refinement/firefox-intelligence-1440.webp)
- [DPS desktop](review/refinement/firefox-dps-1440.webp) · [DPS mobile](review/refinement/firefox-dps-390.webp)
- [Closing transition](review/refinement/firefox-contribute-1440.webp)
- Carousel [Code/Image/Cloud](review/refinement/firefox-applications-group-1.webp), [Browser/Chat/Mail](review/refinement/firefox-applications-group-2.webp), [Map/Weather/Studio](review/refinement/firefox-applications-group-3.webp)

## Verification

- Preview and production build/check pass: local assets and fragments, `/volparossa/`
  isolation, visible DPS text, metadata/indexability, five native disclosures and
  exactly the requested nine applications with Bank/Citizen excluded.
- Chromium 154 and Playwright Firefox 153 pass 320, 390, 768, 1440, 1920 and 2560 px,
  200% computed text size, keyboard menu/disclosures, reduced motion, no JavaScript,
  loaded visible images, no page overflow, console/HTTP errors or third-party requests.
- Four full-page axe scans report zero violations. The carousel’s separate four
  scans also report zero violations (390/1440 in both browsers).
- The final carousel suite traverses every app/icon/link, previous/next wrap, automatic
  six-second advance, pause/start, focus/hover/offscreen stops, reduced-motion changes,
  no-JavaScript fallback and swipe click suppression in both browsers. Five viewport
  widths include 200% text. Its 16 result groups pass. A Firefox lazy-image decode
  race in the initial test harness was corrected to await actual image loading;
  the original note remains with local evidence. No product behavior failed.
- Full-page QA preceded only the isolated swipe-click suppression addition; final
  focused carousel QA covers that change and verifies served CSS/JS against source.
- Independent source review found no blockers in carousel/build integration and
  verified original asset hashes. The smallest appropriate checks were used; no
  Core daemon, networking, sensor, model or native product trial was run.

[Full-page results](review/refinement/browser-results.json) ·
[Carousel results](review/refinement/carousel-results.json) ·
[Carousel tested asset hashes](review/refinement/carousel-source-hashes.json) ·
[Website input hashes](review/refinement/source-binding.json).

## Performance

Lighthouse 13.6.0 against the local production build, standard simulated profiles:

| Profile | Performance | Accessibility | Best practices | SEO | LCP | CLS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Mobile | 93 | 100 | 100 | 100 | 3.2 s | 0 |
| Desktop | 98 | 100 | 100 | 100 | 1.1 s | 0.001 |

Mobile transfer: 436 KiB. Initial gzip CSS/JS: 14,151 bytes. Hero budgets are
unchanged. These are lab results, not field Core Web Vitals. Original reports are
retained as compressed JSON beside the [summary](review/refinement/lighthouse-summary.json).
Safari/WebKit was not tested; the existing environment lacks its system libraries.

## Publication

Use the existing protected pull-request route and scoped Core Pages workflow.
The owner’s publication instruction remains in force. No DNS, root-domain, Pages
source, repository protection or homepage setting is changed. Production review
will be linked from the pull request after deployment.
