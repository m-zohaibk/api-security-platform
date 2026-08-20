"""Run the full scanner pipeline against one already-authorized training page.

The normal discovery routine probes common paths and is intentionally broad. This
harness limits discovery to the requested page while retaining the page's real
form fields and methods, so a focused regression run is practical.
"""
import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.discovery import EndpointDiscovery
import main


def targeted_discover(self):
    self.max_depth = 0
    parsed_base = urlsplit(self.base_url)
    if not parsed_base.path.endswith("/") and not parsed_base.query:
        self.base_url = parsed_base._replace(path=parsed_base.path + "/").geturl()
    self._crawl_page(self.base_url, depth=0)
    by_url = {}
    target_path = urlsplit(self.base_url).path.rstrip("/")
    for ep in self.discovered_endpoints:
        parsed_path = urlsplit(ep.get("url", "")).path.rstrip("/")
        if parsed_path != target_path:
            continue
        existing = by_url.setdefault(self.base_url, dict(ep))
        for key in ("form_fields", "query_fields"):
            merged = list(dict.fromkeys((existing.get(key) or []) + (ep.get(key) or [])))
            if merged:
                existing[key] = merged
        if ep.get("form_defaults"):
            existing["form_defaults"] = {**existing.get("form_defaults", {}), **ep["form_defaults"]}
        if ep.get("form_method"):
            existing["form_method"] = ep["form_method"]
            existing["method"] = ep["form_method"]
    return list(by_url.values())


def main_entry():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    EndpointDiscovery.discover = targeted_discover
    main.run_pipeline(args.url)


if __name__ == "__main__":
    main_entry()
