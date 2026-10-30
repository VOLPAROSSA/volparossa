# VOLPAROSSA Core — Golden Harbour

A static introduction to the developing Core architecture at
<https://volparossa.org/volparossa/>. It runs no Core code, backend, telemetry,
location API, sensor access or model. All visitor assets are served locally.

## Build, preview and check

From the repository root, with Python 3.10 or newer:

```sh
python3 website/build.py --output .volparossa-dev/website-preview/volparossa --preview
python3 website/check_site.py --output .volparossa-dev/website-preview/volparossa --preview
python3 -m http.server 8765 --bind 127.0.0.1 --directory .volparossa-dev/website-preview
```

Open <http://127.0.0.1:8765/volparossa/>. Serving the parent directory exercises
the real project subpath. Preview HTML is `noindex, nofollow`; its canonical
remains the production URL. Stop the server with Ctrl+C when finished.

```sh
python3 website/build.py --output .volparossa-dev/website-dist/volparossa
python3 website/check_site.py --output .volparossa-dev/website-dist/volparossa
```

The **contents** of that final `volparossa` directory form the Pages artifact.
Do not publish its parent or the Core repository. The builder accepts only a new,
empty or previously marked generated directory; it never replaces the website
source. Production has no `noindex`, CNAME or project-level `robots.txt`.

Optional browser QA uses pinned development tools; no Node dependency is shipped:

```sh
cd website
npm ci
# Use already installed browsers, or install the pinned Playwright browsers
# in an approved disposable QA environment.
CHROME_PATH=/path/to/chromium npm run qa
```

`SITE_QA_URL` defaults to the preview URL above. `SITE_QA_OUTPUT` selects a
disposable report/screenshot directory. Chromium and Firefox run at 320, 390,
768, 1440, 1920 and 2560 pixels, including actual font-size doubling, native
details, keyboard navigation, no JavaScript and reduced motion. An absent browser
is a missing QA prerequisite, not a passed test. Results and rendered review
images are summarized in [VERIFICATION.md](VERIFICATION.md).

## Sources and maintenance

- `config.json`: one explicit host URL, project basepath, metadata and upstream
  mark display switch. Keep the trailing slash on the basepath.
- `content.html`, `build.py`, `assets/core.css`: English content, semantic build
  and Golden Harbour composition. Native `details` works without JavaScript.
- `theme/`: unchanged, locally vendored shared design v1.0.3 from reviewed
  homepage commit `8114d966f3e9be878cb6dbb3d155a5739edfeb03`.
  `theme/theme-version.json` records every SHA-256; the build verifies them.
  Header, footer, fonts, buttons, badges, navigation registry/renderer and app
  publication destinations come from this export. There is no runtime `main`
  download or separately maintained Core navigation.
- [CONTENT-SOURCES.md](CONTENT-SOURCES.md): claims audited against Core commit
  `edf569300acbdf5e7715b5192ffbb293235b15ab`, with exact source lines and boundaries.
- [ASSETS.md](ASSETS.md): original marks/notices, artwork provenance and maintenance.
- `artwork/`: lossless masters, exact generation prompts and the selected supplied
  reference, excluded from the published artifact. `prepare_images.py` regenerates
  WebP/JPEG variants and the social image with Pillow 12.3.0. It is not part of the
  production build or a visitor runtime dependency.

To update the theme, review a clean exact homepage commit and run its
`python3 scripts/export_theme.py --source-only --output NEW_EMPTY_DIRECTORY`.
Review the manifest and diff before replacing `theme/`; rerun both builders and
browser QA. Preserve original notices and never patch vendored theme files in
place. Change a shared component upstream and export a new reviewed version.

Application destinations use the frozen shared registry. Unpublished integrations
lead to their real repositories and say “Project repository · GitHub”. General
documentation returns to the central portal. Core and DPS use its real `#core`
and `#dps` entries; a direct DPS source link remains visible. Future portal rendering
belongs in that central portal rather than a second Core documentation system.

## Publication

`.github/workflows/core-website.yml` separates PR validation, production artifact
creation and Pages deployment. PRs receive read-only repository access and a
downloadable noindex preview artifact. Only the main branch can reach the separate
deployment job, which receives Pages/OIDC permissions and the `github-pages`
environment. Official actions are pinned to immutable revisions. Existing Core
quality requirements are preserved; this website workflow invokes no Cargo,
daemon, network, sensor, model or installation trial.

The user explicitly requested publication. The initial repository setup selects
GitHub Actions as the Core project's Pages source; no root-domain, homepage CNAME,
DNS or existing homepage hosting setting is changed. Later relevant main pushes
or a manual main-branch dispatch publish the checked artifact. Review production
before enabling the homepage's Core publication flag. Revert through a normal
reviewed PR and the same workflow if a rollback is needed.

Original site code is GPL-3.0-only. Preserve third-party notices in `theme/`.
