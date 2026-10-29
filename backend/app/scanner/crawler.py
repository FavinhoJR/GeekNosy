"""Small same-origin crawler used only by bug_bounty/deep profiles."""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        attr_map = dict(attrs)
        candidates = []
        if tag in ("a", "link"):
            candidates.append(attr_map.get("href"))
        if tag in ("script", "img", "iframe"):
            candidates.append(attr_map.get("src"))
        if tag == "form":
            candidates.append(attr_map.get("action"))
        for value in candidates:
            if value:
                self.links.append(value)


def discover_same_origin_paths(base_url: str, html: str, max_paths: int = 30) -> list[str]:
    parser = LinkCollector()
    try:
        parser.feed(html[:100_000])
    except Exception:
        return []
    base = urlsplit(base_url)
    discovered = []
    seen = set()
    for link in parser.links:
        absolute = urlsplit(urljoin(base_url, link))
        if absolute.scheme not in ("http", "https") or absolute.hostname != base.hostname:
            continue
        path = absolute.path or "/"
        if absolute.query:
            # Query values can contain secrets; preserve parameter names only.
            names = [part.split("=", 1)[0] for part in absolute.query.split("&") if part]
            path += "?" + "&".join(f"{name}=" for name in names)
        key = path.rstrip("/") or "/"
        if key not in seen:
            seen.add(key)
            discovered.append(path)
        if len(discovered) >= max_paths:
            break
    return discovered
