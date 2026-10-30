#!/usr/bin/env python3
"""Maintenance only: export local responsive images from the lossless masters.

Requires Pillow 12.3.0. The static website build does not need Pillow or imagegen.
"""
import hashlib
import json
from pathlib import Path
from PIL import Image, ImageOps

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / 'assets/harbour'
OUTPUT.mkdir(parents=True, exist_ok=True)
images = {}
provenance = {'generator': 'image_gen.imagegen', 'created': '2026-10-30', 'reference': 'artwork/reference.png', 'reference_sha256': hashlib.sha256((ROOT / 'artwork/reference.png').read_bytes()).hexdigest(), 'images': {}}
for name in ('hero-desktop', 'hero-mobile', 'shared-harbour', 'intelligence', 'dps', 'closing'):
    master = ROOT / 'artwork/masters' / f'{name}.png'
    original = Image.open(master).convert('RGB')
    widths = [480, 800, 1122] if name == 'hero-mobile' else [640, 800, 960, 1280, 1672]
    entries = []
    for width in widths:
        width = min(width, original.width)
        height = round(original.height * width / original.width)
        resized = original.resize((width, height), Image.Resampling.LANCZOS)
        filename = f'{name}-{width}.webp'
        resized.save(OUTPUT / filename, 'WEBP', quality=76 if width <= 960 or name == 'hero-mobile' else 83, method=6)
        fallback = f'{name}-{width}.jpg'
        resized.save(OUTPUT / fallback, 'JPEG', quality=85, optimize=True, progressive=True)
        entries.append({'file': filename, 'fallback': fallback, 'width': width, 'height': height, 'bytes': (OUTPUT / filename).stat().st_size, 'fallback_bytes': (OUTPUT / fallback).stat().st_size})
    images[name] = entries
    provenance['images'][name] = {'master': f'artwork/masters/{name}.png', 'prompt': f'artwork/prompts/{name}.txt', 'sha256': hashlib.sha256(master.read_bytes()).hexdigest(), 'width': original.width, 'height': original.height, 'responsive': entries, 'composition': 'Intentional portrait composition' if name == 'hero-mobile' else 'Full-frame landscape derivatives; no baked text or controls'}
hero = Image.open(ROOT / 'artwork/masters/hero-desktop.png').convert('RGB')
ImageOps.fit(hero, (1200, 630), method=Image.Resampling.LANCZOS, centering=(.5, .5)).save(OUTPUT / 'social.jpg', 'JPEG', quality=88, optimize=True, progressive=True)
(OUTPUT / 'images.json').write_text(json.dumps(images, indent=2) + '\n')
(ROOT / 'artwork/provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
print(f'Exported {sum(len(x) for x in images.values())} responsive images and the 1200 × 630 social preview.')
