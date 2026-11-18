#!/usr/bin/env python3
"""Check a generated Core website offline; never start or install Core services."""

import argparse
import gzip
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urljoin, urlsplit
import xml.etree.ElementTree as ET

ORIGIN = "https://volparossa.org"
BASE_PATH = "/volparossa/"
CANONICAL = ORIGIN + BASE_PATH
SECTIONS = {"overview", "layers", "applications", "intelligence", "dps", "contribute"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
RESOURCE_TAGS = {"img", "source", "script", "image", "use"}
RESOURCE_RELS = {"stylesheet", "icon", "preload", "modulepreload"}


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.stack = []
        self.ids = set()
        self.references = []
        self.errors = []
        self.metadata = {}
        self.links = {}
        self.headings = []
        self.visible = {}
        self.details = {}
        self.applications = []
        self.landmarks = []
        self.title = ""
        self.lang = ""
        self.skip = False

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        if tag == "html":
            self.lang = attrs.get("lang", "")
        if tag in {"main", "header", "footer", "nav"}:
            self.landmarks.append(tag)
        if tag in {"iframe", "embed", "object", "form", "base"}:
            self.errors.append(f"Unexpected embedded or active content: {tag}")
        if any(key.startswith("on") for key in attrs):
            self.errors.append("Inline event handler")
        if tag == "script" and (not attrs.get("src") or "defer" not in attrs):
            self.errors.append("Scripts must be local, external and deferred")
        if tag == "article" and "data-app" in attrs:
            self.applications.append(attrs["data-app"])
        identifier = attrs.get("id")
        if identifier:
            if identifier in self.ids:
                self.errors.append(f"Duplicate ID: {identifier}")
            self.ids.add(identifier)
        if tag == "meta":
            key = attrs.get("name", attrs.get("property"))
            if key:
                if key in self.metadata:
                    self.errors.append(f"Duplicate metadata: {key}")
                self.metadata[key] = attrs.get("content", "")
        if tag == "link":
            self.links[attrs.get("rel", "")] = attrs.get("href", "")
        if tag == "a" and "skip-link" in attrs.get("class", "").split():
            self.skip = attrs.get("href") == "#main"
        if tag == "img":
            if "alt" not in attrs:
                self.errors.append("Image is missing its alt attribute")
            if not attrs.get("width", "").isdigit() or not attrs.get("height", "").isdigit():
                self.errors.append("Image is missing explicit intrinsic dimensions")
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(int(tag[1]))
        if tag == "details":
            for _, parent in self.stack:
                if parent.get("id") in SECTIONS:
                    section = parent["id"]
                    self.details[section] = self.details.get(section, 0) + 1
        resource = tag in RESOURCE_TAGS or (tag == "link" and attrs.get("rel") in RESOURCE_RELS)
        for name in ("href", "src", "poster"):
            if name in attrs:
                self.references.append((attrs[name], resource or name == "poster"))
        for item in attrs.get("srcset", "").split(","):
            if item.strip():
                self.references.append((item.strip().split()[0], True))
        for ref in attrs.get("aria-labelledby", "").split():
            self.references.append(("#" + ref, False))
        if tag not in VOID:
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1][0] != tag:
            self.errors.append(f"Unbalanced end tag: {tag}")
        else:
            self.stack.pop()

    def handle_startendtag(self, tag, pairs):
        self.handle_starttag(tag, pairs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_data(self, text):
        if self.stack and self.stack[-1][0] == "title":
            self.title += text
        hidden = any(tag in {"script", "style", "head", "title"} or "hidden" in attrs or attrs.get("aria-hidden") == "true" for tag, attrs in self.stack)
        if not hidden:
            for _, attrs in self.stack:
                if attrs.get("id") in SECTIONS:
                    self.visible.setdefault(attrs["id"], []).append(text)

    def text(self, section):
        return " ".join(" ".join(self.visible.get(section, [])).split())


def check_site(output, preview=False):
    output = output.resolve()
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    require((output / "index.html").is_file(), "Missing generated index.html")
    require((output / ".nojekyll").is_file(), "Missing .nojekyll")
    require(not (output / "CNAME").exists(), "A project artifact must not set the root custom domain")
    require(not (output / "robots.txt").exists(), "robots.txt belongs to the host root, not this project subpath")
    for path in output.rglob("*"):
        require(not path.is_symlink(), f"Artifact contains a symlink: {path.relative_to(output)}")
        require(path.name not in {".git", ".github", "Cargo.toml", "Cargo.lock", "AGENTS.md"}, f"Repository internals in public artifact: {path.name}")

    pages = {}
    for path in sorted(output.rglob("*.html")):
        source = path.read_text(encoding="utf-8")
        page = Page(path)
        page.feed(source)
        page.close()
        pages[path.resolve()] = page
        label = path.relative_to(output).as_posix()
        errors.extend(f"{label}: {message}" for message in page.errors)
        require(not re.search(r"\{\{[^}]+\}\}", source), f"{label}: unexpanded template value")
        require(not page.stack, f"{label}: unclosed HTML elements")
        require(page.lang == "en", f"{label}: expected English document language")
        require("VOLPAROSSA" in page.title and len(page.title.strip()) > 15, f"{label}: missing descriptive title")
        require(page.landmarks.count("main") == 1 and "header" in page.landmarks and "footer" in page.landmarks and "nav" in page.landmarks, f"{label}: missing semantic landmarks")
        require(page.skip and "main" in page.ids, f"{label}: missing working skip link")
        require(page.headings and page.headings[0] == 1 and page.headings.count(1) == 1, f"{label}: expected one first-level heading")
        require(all(right <= left + 1 for left, right in zip(page.headings, page.headings[1:])), f"{label}: skipped heading level")
        for key in ("description", "viewport", "og:title", "og:description", "og:url", "og:image", "og:image:alt", "twitter:card"):
            require(bool(page.metadata.get(key)), f"{label}: missing {key} metadata")
        if preview or path.name == "404.html":
            require("noindex" in page.metadata.get("robots", ""), f"{label}: preview/error page must be noindex")
        else:
            require("noindex" not in page.metadata.get("robots", ""), f"{label}: production page is noindex")
        for key in ("og:image", "twitter:image"):
            if page.metadata.get(key):
                page.references.append((page.metadata[key], True))

    def reference(value, from_path, resource=False):
        label = from_path.relative_to(output).as_posix()
        if not value:
            errors.append(f"{label}: empty link or asset URL")
            return
        if value.startswith("data:"):
            return
        current = CANONICAL + from_path.relative_to(output).as_posix()
        target = urlsplit(urljoin(current, value))
        require(target.scheme in {"https", "http", "mailto", "tel"}, f"{label}: unsafe URL scheme in {value}")
        if target.scheme in {"mailto", "tel"}:
            require(not resource, f"{label}: invalid resource URL {value}")
            return
        own_project = target.netloc == "volparossa.org" and target.path.startswith(BASE_PATH)
        if resource:
            require(own_project, f"{label}: resource escapes the Core project basepath: {value}")
        if not own_project:
            return  # Main-site and GitHub links are checked separately against live deployment.
        relative = unquote(target.path[len(BASE_PATH):])
        resolved = (output / relative).resolve()
        require(resolved.is_relative_to(output), f"{label}: path escapes artifact: {value}")
        if not resolved.is_relative_to(output):
            return
        if target.path.endswith("/"):
            resolved /= "index.html"
        require(resolved.is_file(), f"{label}: missing local target {value}")
        if target.fragment:
            page = pages.get(resolved)
            require(page is not None and unquote(target.fragment) in page.ids, f"{label}: missing fragment {value}")

    for path, page in pages.items():
        for value, resource in page.references:
            reference(value, path, resource)
    for path in output.rglob("*.css"):
        css = path.read_text(encoding="utf-8")
        for match in re.finditer(r"url\(\s*['\"]?([^)'\"]+)['\"]?\s*\)", css):
            reference(match.group(1).strip(), path, True)
        require(not re.search(r"@import\s+['\"]", css), f"{path.name}: runtime CSS imports are not allowed")
    for path in output.rglob("*.js"):
        js = path.read_text(encoding="utf-8")
        require(not re.search(r"\bfetch\s*\(|\b(?:XMLHttpRequest|WebSocket|EventSource|sendBeacon|getUserMedia|geolocation|DeviceOrientationEvent|DeviceMotionEvent|AbsoluteOrientationSensor|Gyroscope|Accelerometer)\b", js), f"{path.name}: unexpected remote, tracking or sensor capability")

    index = pages.get((output / "index.html").resolve())
    if index:
        require(SECTIONS <= index.ids, "Missing required Core sections")
        expected_apps = {"code", "image", "cloud", "browser", "chat", "mail", "map", "weather", "studio"}
        require(set(index.applications) == expected_apps and len(index.applications) == 9, "Carousel must include each requested application once, excluding Bank and Citizen")
        require(index.links.get("canonical") == CANONICAL, "Incorrect Core production canonical")
        require(index.metadata.get("og:url") == CANONICAL, "Incorrect Core Open Graph URL")
        require(index.details.get("layers") == 5, "Each of the five layers needs one native disclosure")
        for section, required in {
            "overview": ["The foundation for shared possibilities.", "Development preview"],
            "layers": ["Network", "Cache", "Storage", "Compute", "Transactions"],
            "applications": ["One core. Many applications.", "Code", "Image", "Cloud", "Integration in development"],
            "intelligence": ["Intelligence beyond a single device.", "In development"],
            "dps": ["DPS — Decentralized Positioning System", "Find your way, together.", "Privacy-preserving positioning", "Research & development", "Multiple sources", "Visible uncertainty", "Explicit permissions"],
            "contribute": ["Help build the common ground.", "Participation is voluntary. Joining the network means accepting its resource-sharing responsibilities."],
        }.items():
            for text in required:
                require(text in index.text(section), f"{section}: required visible text missing: {text}")
        require(any(value == ORIGIN + "/docs/#dps" for value, _ in index.references), "Missing central DPS documentation link")
        require(any("github.com/VOLPAROSSA/volparossa/" in value and value.endswith("docs/services/DPS.md") for value, _ in index.references), "Missing direct DPS source fallback")

    sitemap = output / "sitemap.xml"
    require(sitemap.is_file(), "Missing project sitemap")
    if sitemap.is_file():
        try:
            root = ET.fromstring(sitemap.read_text(encoding="utf-8"))
            locations = [node.text for node in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
            require(CANONICAL in locations, "Sitemap omits the actual Core route")
            for value in locations:
                reference(value or "", sitemap)
        except ET.ParseError as exc:
            errors.append(f"Invalid sitemap XML: {exc}")
    script_style_bytes = sum(len(gzip.compress(path.read_bytes())) for path in output.rglob("*") if path.suffix in {".css", ".js"})
    require(script_style_bytes <= 150_000, f"Compressed CSS/JS exceeds 150 kB: {script_style_bytes} bytes")
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"Core website checks passed: {len(pages)} HTML page(s), local URLs/fragments, required visible content, metadata, artifact isolation; {script_style_bytes:,} bytes gzip CSS/JS.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Generated project artifact root, containing index.html")
    parser.add_argument("--preview", action="store_true", help="Require preview noindex metadata")
    args = parser.parse_args()
    raise SystemExit(check_site(args.output, args.preview))
