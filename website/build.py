#!/usr/bin/env python3
"""Build only the Golden Harbour project site, using Python's standard library."""
import argparse
import hashlib
from html import escape
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

from applications import render_applications

HERE = Path(__file__).resolve().parent
THEME = HERE / 'theme'
CONFIG = json.loads((HERE / 'config.json').read_text())
BASE = CONFIG['base_path']
ORIGIN = CONFIG['site_url'].rstrip('/')
REPOSITORY = CONFIG['repository']
CANONICAL = ORIGIN + BASE


def render(source, values):
    return re.sub(r'\{\{([a-z_]+)\}\}', lambda m: str(values[m[1]]) if m[1] in values else m[0], source)


def icon(name):
    upstream = {'compute': 'settings', 'sources': 'satellite'}
    if name in upstream:
        svg = (HERE / 'assets/icons/lucide' / f'{upstream[name]}.svg').read_text()
        return re.sub(r'<svg\b[^>]*>', '<svg class="core-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">', svg, count=1)
    shapes = {
        'network': '<circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><path d="m10.5 7.5-4 8.8m7-8.8 4 8.8M8 19h8"/>',
        'cache': '<ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v14c0 4 14 4 14 0V5M5 12c0 4 14 4 14 0"/>',
        'storage': '<path d="m12 2 9 5v10l-9 5-9-5V7Zm0 10v10M3 7l9 5 9-5"/>',
        'transactions': '<rect x="5" y="2" width="14" height="20" rx="1"/><path d="M9 7h1m3 0h3M9 12h1m3 0h3M9 17h7"/>',
        'uncertainty': '<circle cx="12" cy="12" r="9" stroke-dasharray="1.5 4"/><circle cx="12" cy="12" r="2"/>',
        'permissions': '<path d="m12 2 8 4v6c0 5-8 10-8 10S4 17 4 12V6Z"/><path d="m8 12 3 3 5-6"/>',
    }
    return f'<svg class="core-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{shapes[name]}</svg>'


def picture(name, manifest, mobile=None, eager=False):
    data = manifest[name]
    def source_set(items, key='file'):
        return ', '.join(f'{BASE}assets/harbour/{i[key]} {i["width"]}w' for i in items)
    source = ''
    if mobile:
        md = manifest[mobile]
        source = ''.join(f'<source type="image/{kind}" media="(max-width: 800px)" srcset="{source_set(md, key)}" sizes="100vw" width="{md[-1]["width"]}" height="{md[-1]["height"]}">' for kind, key in [('webp', 'file'), ('jpeg', 'fallback')])
    largest = data[-1]
    attributes = 'fetchpriority="high" loading="eager"' if eager else 'loading="lazy" decoding="async"'
    return f'<picture class="core-media">{source}<source type="image/webp" srcset="{source_set(data)}" sizes="100vw"><img src="{BASE}assets/harbour/{data[0]["fallback"]}" srcset="{source_set(data, "fallback")}" sizes="100vw" width="{largest["width"]}" height="{largest["height"]}" alt="" {attributes}></picture>'


def layers():
    rows = [
        ('network', 'Network', 'Connect participating devices.', 'Useful parallel routes connect participants through different relays. Each normal Internet path keeps one relay between the client and exit.', 'architecture/ARCHITECTURE.md'),
        ('cache', 'Cache', 'Reuse eligible public content.', 'Reuse verified public content when its source and permissions allow sharing. Private files and arbitrary encrypted web traffic do not become shared cache entries.', 'services/CONTENT_NETWORK_PROPOSAL.md'),
        ('storage', 'Storage', 'Keep encrypted private files recoverable.', 'Applications encrypt files before sharing fragments and recovery copies. Owners keep their recovery keys; providers hold ciphertext. Complete maintenance and application recovery remain in development.', 'services/PRIVATE_STORAGE.md'),
        ('compute', 'Compute', 'Share suitable work and models.', 'Divide suitable tasks, combine results and reuse permitted models. Confidential execution of private work on other participants’ devices remains unfinished.', 'services/DECENTRALIZED_AGENTS.md'),
        ('transactions', 'Transactions', 'Record authorized test transfers.', 'Explore authorized transfers and durable accounting with fictitious test value. This is not a live banking or payment service.', 'services/TRANSACTION_LAYER.md'),
    ]
    return '\n'.join(f'<details class="core-layer"><summary>{icon(key)}<h3>{name}</h3><span class="core-layer-short">{short}</span><span class="core-detail-cue">Explore {name.lower()}</span></summary><div class="core-layer-more"><p>{body}</p><a href="{REPOSITORY}/blob/main/docs/{path}">{name} documentation ↗</a></div></details>' for key, name, short, body, path in rows)


def build(output, preview=False):
    output = output.resolve()
    repo = HERE.parent
    if output == repo or output == HERE or HERE in output.parents or output in HERE.parents:
        raise SystemExit('Choose a separate generated output directory outside website/.')
    marker = '.core-website-output'
    if output.exists() and any(output.iterdir()) and not (output / marker).is_file():
        raise SystemExit('Refusing to replace a nonempty directory not created by this builder.')
    manifest = json.loads((THEME / 'theme-version.json').read_text())
    for path, digest in manifest['files'].items():
        if hashlib.sha256((THEME / path).read_bytes()).hexdigest() != digest:
            raise SystemExit(f'Pinned theme file differs from its manifest: {path}')
    spec = importlib.util.spec_from_file_location('shared_navigation', THEME / 'shared/navigation.py')
    navigation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(navigation)
    nav_config = json.loads((THEME / 'data/navigation.json').read_text())
    projects = json.loads((THEME / 'data/projects.json').read_text())
    links = navigation.site_links(nav_config, projects, ORIGIN + '/', {'core': CANONICAL, 'github': REPOSITORY})
    github = (THEME / 'assets/icons/github.svg').read_text()
    # The original Octicon path and its MIT notice remain unchanged.
    github = re.sub(r'^<svg[^>]*>', '<svg class="github-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">', github.strip())
    images = json.loads((HERE / 'assets/harbour/images.json').read_text())
    values = {
        **links, 'root': BASE, 'site_url': ORIGIN, 'repository': REPOSITORY,
        'title': escape(CONFIG['title']), 'description': escape(CONFIG['description'], quote=True),
        'canonical': CANONICAL, 'body_class': 'core-page',
        'social_image': CANONICAL + 'assets/harbour/social.jpg',
        'social_alt': 'A red fox on a sheltered quay overlooking the Golden Harbour at sunset.',
        'github_icon': github,
        'head_extra': f'<link rel="stylesheet" href="{BASE}assets/core.css"><link rel="stylesheet" href="{BASE}assets/carousel.css"><script src="{BASE}assets/carousel.js" defer></script>' + ('<meta name="robots" content="noindex, nofollow">' if preview else ''),
        'nav_links': navigation.navigation_links(nav_config['main'], links, 'core', github),
        'footer_links': navigation.navigation_links(nav_config['footer'], links, 'core', github, footer=True),
        'hero_picture': picture('hero-desktop', images, 'hero-mobile', eager=True),
        'layers_picture': picture('shared-harbour', images),
        'intelligence_picture': picture('intelligence', images),
        'dps_picture': picture('dps', images),
        'closing_picture': picture('closing', images),
        'layer_details': layers(), 'application_strip': render_applications(THEME, BASE, CONFIG['upstream_marks']),
        'sources_icon': icon('sources'), 'uncertainty_icon': icon('uncertainty'), 'permissions_icon': icon('permissions'),
    }
    for name in ('header', 'footer'):
        values[name] = render((THEME / f'templates/{name}.html').read_text(), values)
    values['content'] = render((HERE / 'content.html').read_text(), values)
    html = render((THEME / 'templates/layout.html').read_text(), values)
    html = html.replace('↗', '<svg class="external-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M4 12 12 4M4 4h8v8"/></svg>')
    if re.search(r'\{\{[a-z_]+\}\}', html):
        raise SystemExit('An unexpanded template variable remains.')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.core-build-', dir=output.parent))
    try:
        shutil.copytree(THEME / 'assets', temporary / 'assets')
        shutil.copytree(HERE / 'assets', temporary / 'assets', dirs_exist_ok=True)
        # Metadata and lossless masters are build inputs, never visitor payloads.
        (temporary / 'assets/harbour/images.json').unlink()
        shutil.copy2(THEME / 'LICENSE', temporary / 'LICENSE')
        shutil.copy2(THEME / 'favicon.ico', temporary / 'favicon.ico')
        (temporary / 'index.html').write_text(html, encoding='utf-8')
        (temporary / '.nojekyll').touch()
        (temporary / marker).write_text('Generated by website/build.py. Rebuildable output only.\n')
        (temporary / 'sitemap.xml').write_text(f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{CANONICAL}</loc></url></urlset>\n')
        if output.exists():
            shutil.rmtree(output)
        temporary.rename(output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    print(f'Built {"noindex preview" if preview else "production"} at {output} (theme {manifest["version"]}, {BASE}).')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--preview', action='store_true')
    args = parser.parse_args()
    build(args.output, args.preview)
