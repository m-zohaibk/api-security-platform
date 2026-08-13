from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger

class EndpointDiscovery:
    """
    Crawls a base URL to automatically discover API endpoints, forms,
    and links without requiring an OpenAPI specification document.
    """

    COMMON_API_PATHS = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/v1",
        "/v2",
        "/health",
        "/status",
        "/users",
        "/users/v1",
        "/users/v1/login",
        "/users/v1/register",
        "/users/v1/debug",
        "/users/v1/1",
        "/auth",
        "/login",
        "/createdb"
    ]

    def __init__(self, base_url: str, timeout: float = 10.0, max_depth: int = 2):
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme or "http"
        self.timeout = timeout
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[Dict[str, str]] = []

    def is_same_domain(self, url: str) -> bool:
        parsed = urlparse(url)
        return not parsed.netloc or parsed.netloc == self.domain

    def normalize_url(self, url: str) -> str:
        joined = urljoin(self.base_url, url)
        parsed = urlparse(joined)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def discover(self) -> List[Dict[str, str]]:
        """
        Executes endpoint discovery by crawling HTML pages and probing common API paths.
        Returns a list of dicts with 'url' and 'method'.
        """
        logger.info(f"Starting endpoint discovery on target: {self.base_url}")
        print(f"\n[+] Starting Endpoint Discovery for: {self.base_url}")

        self._crawl_page(self.base_url, depth=0)
        self._probe_common_paths()

        # Deduplicate results
        unique_endpoints: List[Dict[str, str]] = []
        seen = set()
        for ep in self.discovered_endpoints:
            identifier = f"{ep['method']}:{ep['url']}"
            if identifier not in seen:
                seen.add(identifier)
                unique_endpoints.append(ep)

        self.discovered_endpoints = unique_endpoints

        print(f"\n[+] Discovery complete. Found {len(self.discovered_endpoints)} unique endpoints:")
        for idx, ep in enumerate(self.discovered_endpoints, start=1):
            print(f"  {idx}. [{ep['method']}] {ep['url']}")

        return self.discovered_endpoints

    def _crawl_page(self, current_url: str, depth: int) -> None:
        if depth > self.max_depth or current_url in self.visited_urls:
            return

        self.visited_urls.add(current_url)

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(current_url)
                
                # Record initial GET endpoint if successful
                if response.status_code < 400:
                    self.discovered_endpoints.append({"url": current_url, "method": "GET"})

                # Parse HTML content if available
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type:
                    soup = BeautifulSoup(response.text, "html.parser")

                    # Extract links (<a> tags)
                    for a_tag in soup.find_all("a", href=True):
                        href = a_tag["href"]
                        if href and not href.startswith(("#", "javascript:", "mailto:")):
                            full_url = self.normalize_url(href)
                            if self.is_same_domain(full_url):
                                self.discovered_endpoints.append({"url": full_url, "method": "GET"})
                                if depth < self.max_depth:
                                    self._crawl_page(full_url, depth + 1)

                    # Extract forms (<form> tags)
                    for form in soup.find_all("form"):
                        action = form.get("action", "")
                        method = form.get("method", "GET").upper()
                        form_url = self.normalize_url(action) if action else current_url
                        if self.is_same_domain(form_url):
                            self.discovered_endpoints.append({"url": form_url, "method": method})

        except httpx.RequestError as exc:
            logger.warning(f"Request error while crawling {current_url}: {exc}")
        except Exception as exc:
            logger.error(f"Unexpected error crawling {current_url}: {exc}")

    def _probe_common_paths(self) -> None:
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            for relative_path in self.COMMON_API_PATHS:
                target_url = f"{self.base_url}{relative_path}"
                if target_url not in self.visited_urls:
                    try:
                        resp = client.get(target_url)
                        if resp.status_code < 404:
                            self.discovered_endpoints.append({"url": target_url, "method": "GET"})
                    except httpx.RequestError:
                        continue


if __name__ == "__main__":
    import sys
    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://httpbin.org"
    discoverer = EndpointDiscovery(base_url=test_url)
    results = discoverer.discover()
