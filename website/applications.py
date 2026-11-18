"""Build the Core application carousel from the pinned shared project registry."""
from html import escape
import json
from pathlib import Path

EXCLUDED = {'bank', 'citizen'}
# Assets remain original upstream marks; OpenCode and Immich are in the shared theme.
MARKS = {
    'code': [('upstream/opencode.svg', 'OpenCode', 40, 50)],
    'image': [('upstream/immich.svg', 'Immich', 64, 64)],
    'cloud': [('apps/opencloud.svg', 'OpenCloud', 512, 512)],
    'browser': [('apps/firefox.png', 'Firefox', 196, 196)],
    'chat': [('apps/signal.svg', 'Signal', 64, 64)],
    'mail': [('apps/thunderbird.png', 'Thunderbird', 196, 196)],
    'map': [('apps/organic-maps.png', 'Organic Maps', 192, 192)],
    'weather': [('apps/drizzli.svg', 'Drizz.li', 64, 64), ('apps/overmorrow.png', 'Overmorrow', 192, 192)],
    'studio': [('apps/silex.svg', 'Silex', 64, 64)],
}
SUMMARIES = {
    'code': 'Coding workflows and cooperative AI.',
    'image': 'Your photos, with a shared storage foundation.',
    'cloud': 'Files and collaboration across a shared network.',
    'browser': 'Familiar browsing, with protected connectivity and shared AI.',
    'chat': 'Messaging, calls and private backups, built on Signal.',
    'mail': 'Existing email accounts and a path toward cooperative delivery.',
    'map': 'Offline maps, navigation and shared positioning research.',
    'weather': 'Public weather-model data, shared through Core.',
    'studio': 'Visual website creation, portable export and shared hosting research.',
}


def render_applications(theme: Path, base: str, show_marks: bool = True) -> str:
    """All non-excluded registry applications stay reachable without JavaScript."""
    registry = json.loads((theme / 'data/applications.json').read_text())
    cards = []
    for app in registry:
        key = app['id']
        if key in EXCLUDED:
            continue
        if key not in MARKS or key not in SUMMARIES:
            raise ValueError(f'Add an original icon and concise summary for {key}.')
        marks = ''.join(
            f'<img src="{base}assets/{filename}" width="{width}" height="{height}" '
            f'alt="{escape(name)} icon" loading="lazy" decoding="async">'
            for filename, name, width, height in MARKS[key]
        ) if show_marks else ''
        brand = f'<span class="core-carousel-mark">{marks}</span>' if marks else ''
        url = app['publication_url'] if app['published'] else app['repository']
        destination = 'Application website' if app['published'] else 'Project repository · GitHub ↗'
        cards.append(
            f'<article class="core-carousel-card core-carousel-{key}" data-app="{key}" '
            f'aria-labelledby="carousel-{key}-title">'
            f'<div class="core-carousel-brand">{brand}<div><h3 id="carousel-{key}-title">{escape(app["name"])}</h3>'
            f'<a class="core-carousel-upstream" href="{escape(app["upstream_url"], quote=True)}">'
            f'Built on {escape(app["upstream"])}</a></div></div>'
            f'<p class="core-carousel-description">{SUMMARIES[key]}</p>'
            f'<span class="status">{escape(app["status"])}</span>'
            f'<a class="core-carousel-explore" href="{escape(url, quote=True)}">Explore {escape(app["name"])} '
            f'<span aria-hidden="true">→</span></a>'
            f'<p class="core-carousel-destination">{destination}</p></article>'
        )
    return (
        '<div class="core-carousel wrap" data-carousel role="region" aria-label="Applications">'
        '<div class="core-carousel-controls" hidden>'
        '<button class="core-carousel-rotation" type="button" data-carousel-rotation>Pause rotation</button>'
        '<div class="core-carousel-navigation">'
        '<button type="button" data-carousel-previous aria-label="Previous applications" aria-controls="core-carousel-track">'
        '<span aria-hidden="true">←</span></button>'
        '<span class="core-carousel-count" data-carousel-count></span>'
        '<button type="button" data-carousel-next aria-label="Next applications" aria-controls="core-carousel-track">'
        '<span aria-hidden="true">→</span></button></div></div>'
        '<div class="core-carousel-viewport"><div class="core-carousel-track" id="core-carousel-track">'
        + '\n'.join(cards) + '</div></div>'
        '<p class="core-carousel-announcement" data-carousel-announcement aria-live="polite" aria-atomic="true"></p>'
        '</div>'
    )
