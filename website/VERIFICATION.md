# Golden Harbour verification — 30 October 2026

This is website evidence only. No Core runtime, network participation, sensor,
model, native installation or financial test was run. The existing Core quality
gate remains required through the normal PR process.

## Later visual refinement

The owner requested closer scene matching and an automatic carousel of all nine
non-Bank/Citizen applications. Current results and screenshots are in
[refinement verification](REFINEMENT-VERIFICATION.md). The following record and
its original artifacts describe the first publication and are retained unchanged.

## Checked result

- Python preview and production builds pass the offline site checker: semantic
  landmarks/headings, local URLs and fragments, every responsive image/font,
  `/volparossa/` isolation, canonical/social metadata, sitemap, preview noindex,
  required visible DPS text and five native layer disclosures.
- Independently tested six corruptions: root `/assets` leakage, broken fragment,
  hidden DPS subheadline, removed preview noindex, geolocation code and a root
  CNAME. Each is rejected. All direct Core source destinations exist.
- Chromium 154 and Playwright Firefox 153 pass at 320, 390, 768, 1440, 1920 and
  2560 CSS pixels. Each also passes a 200% computed-font-size check without
  viewport reduction, horizontal overflow or header/title overlap.
- Four axe scans (390/1440 in both browsers, WCAG 2 A/AA, 2.1 A/AA and 2.2 AA)
  report zero violations. These automated scans supplement visual and keyboard
  review; they are not a claim of complete accessibility certification.
- Keyboard skip link, mobile menu and Escape, all five disclosures, DPS research
  details and hero anchor work. The menu and disclosures also work without
  JavaScript. Reduced motion disables smooth scrolling. No console errors,
  missing images or third-party visitor requests were observed.
- Original shared logo RGBA pixels match the supplied 853 × 853 logo. Upstream
  SVG originals remain byte-for-byte pinned in the shared theme. WebP scenes
  have local JPEG fallbacks, including the separate portrait hero.

The actual renders were compared with the selected harbour reference. Refinements
include a full-frame desktop hero, intentional mobile fox/quay composition,
compact application strip, a shorter workshop composition, prominent independent
DPS section, visible privacy subheadline, and wide soft paper-to-photo transitions
in DPS and the closing invitation. All scene text and controls remain HTML.

## Performance

Lighthouse 13.6.0, local production build over HTTP, standard simulated mobile and
desktop profiles. Scores vary with the test environment; these are lab results.

| Profile | Performance | Accessibility | Best practices | SEO | LCP | CLS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Mobile | 93 | 100 | 100 | 100 | 3.2 s | 0 |
| Desktop | 96 | 100 | 100 | 100 | 1.4 s | 0.001 |

Mobile transfer is approximately 460 KiB. The largest mobile hero is 239,328 bytes;
the largest desktop hero is 302,008 bytes. Total gzip CSS/JavaScript is 11,085 bytes.
The first mobile run scored 89; responsive 800-pixel variants and lighter mobile
WebP compression reduced its 630 KiB transfer. The original report is retained
separately alongside the successful runs.

## Review artifacts

- [Desktop, Firefox](review/firefox-1440.webp)
- [Mobile, Firefox](review/firefox-390.webp)
- [Large desktop hero, Firefox at 2560 px](review/firefox-hero-2560.webp)
- [DPS desktop](review/firefox-dps-1440.webp) and [DPS mobile](review/firefox-dps-390.webp)
- [Workshop](review/firefox-intelligence-1440.webp) and [closing transition](review/firefox-contribute-1440.webp)
- [Mobile, Chromium](review/chromium-390.webp)
- [Browser results](review/browser-results.json), [Lighthouse summary](review/lighthouse-summary.json)
  and [source hashes](review/source-binding.json)

Full original Lighthouse JSON reports are retained as `.json.gz` in `review/`.
Safari/WebKit was not run: its required system libraries are unavailable in this
workspace. Standard semantic HTML, CSS and JPEG fallbacks are provided; no Safari
test result is claimed.

The shared homepage integration was separately checked at exact source
`8114d966f3e9be878cb6dbb3d155a5739edfeb03`: nine static pages, 40 responsive checks,
16 axe scans, 200% text reflow and no-JavaScript subpath export in Chromium/Firefox.
Its Core publication flag is activated only after the Core production route works.
