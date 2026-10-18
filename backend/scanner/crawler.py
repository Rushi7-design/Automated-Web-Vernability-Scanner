"""
scanner/crawler.py
──────────────────────────────────────────────────────────────────────────────
BFS-based web crawler — Phase 2 of the scanning pipeline.

Crawls all pages within the target domain scope using Breadth-First Search.
Extracts:
  • All discovered hyperlinks (within scope)
  • HTML forms (action URL, method, input fields)
  • Query parameters from GET URLs
  • Respects robots.txt (optional)
"""

import json
import logging
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Common file extensions to skip (not useful for vulnerability testing)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".pdf", ".zip", ".rar", ".tar", ".gz",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
}

REQUEST_HEADERS = {
    "User-Agent": "AutoScanner/1.0 (Academic Research - Authorized Testing)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


class CrawlerModule:
    """
    BFS web crawler that discovers pages and forms within the target domain.

    Usage:
        crawler = CrawlerModule(base_url="http://target.com", max_depth=3)
        pages = crawler.crawl()
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        timeout: int = 10,
        respect_robots: bool = True,
        progress_callback=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(base_url)
        self.base_domain = self.parsed_base.netloc
        self.max_depth  = max_depth
        self.max_pages  = max_pages
        self.timeout    = timeout
        self.respect_robots = respect_robots
        self.progress_callback = progress_callback or (lambda msg: None)

        self.visited_urls: set  = set()
        self.crawled_pages: list = []   # list of page dicts
        self._robot_parser: RobotFileParser | None = None

    # ── ROBOTS.TXT ────────────────────────────────────────────────────────────
    def _load_robots(self):
        robots_url = f"{self.parsed_base.scheme}://{self.base_domain}/robots.txt"
        rp = RobotFileParser()
        rp.set_url(robots_url)
        try:
            rp.read()
        except Exception:
            pass
        self._robot_parser = rp

    def _is_allowed(self, url: str) -> bool:
        if not self.respect_robots or self._robot_parser is None:
            return True
        return self._robot_parser.can_fetch("*", url)

    # ── URL HELPERS ───────────────────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        """Check the URL is within the target domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain

    def _normalize(self, url: str, base: str) -> str | None:
        """Normalize URL — resolve relative paths, strip fragments."""
        try:
            full = urljoin(base, url)
            parsed = urlparse(full)
            # Strip fragment
            normalized = urlunparse((
                parsed.scheme, parsed.netloc,
                parsed.path, parsed.params,
                parsed.query, ""
            ))
            # Skip non-HTTP schemes and unwanted extensions
            if parsed.scheme not in ("http", "https"):
                return None
            ext = "." + parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
            if ext in SKIP_EXTENSIONS:
                return None
            return normalized
        except Exception:
            return None

    # ── PAGE FETCH ────────────────────────────────────────────────────────────
    def _fetch(self, url: str) -> requests.Response | None:
        try:
            resp = requests.get(
                url,
                headers=REQUEST_HEADERS,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            return resp
        except requests.RequestException as e:
            logger.debug(f"[Crawler] Fetch error {url}: {e}")
            return None

    # ── LINK EXTRACTION ───────────────────────────────────────────────────────
    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list:
        links = []
        for tag in soup.find_all("a", href=True):
            norm = self._normalize(tag["href"], page_url)
            if norm and self._in_scope(norm) and norm not in self.visited_urls:
                links.append(norm)
        return links

    # ── FORM EXTRACTION ───────────────────────────────────────────────────────
    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list:
        """Return a list of form descriptors found on the page."""
        forms = []
        for form in soup.find_all("form"):
            action  = form.get("action", "")
            method  = form.get("method", "get").upper()
            action_url = urljoin(page_url, action) if action else page_url

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inp_type = inp.get("type", "text")
                    default  = inp.get("value", "test")
                    inputs.append({"name": name, "type": inp_type, "value": default})

            forms.append({
                "action_url": action_url,
                "method":     method,
                "inputs":     inputs,
            })
        return forms

    # ── QUERY PARAM EXTRACTION ────────────────────────────────────────────────
    def _extract_get_params(self, url: str) -> dict:
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    # ── BFS CRAWL ─────────────────────────────────────────────────────────────
    def crawl(self) -> list:
        """
        Perform BFS crawl starting from base_url.
        Returns list of page dicts with url, method, params, status_code, forms.
        """
        self.progress_callback("=== Starting BFS Crawler ===")

        if self.respect_robots:
            self._load_robots()

        queue = deque([(self.base_url, 0)])   # (url, depth)
        self.visited_urls.add(self.base_url)

        while queue and len(self.crawled_pages) < self.max_pages:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            if not self._is_allowed(url):
                self.progress_callback(f"[robots.txt] Skipping: {url}")
                continue

            self.progress_callback(f"Crawling [{depth}]: {url}")
            resp = self._fetch(url)
            if not resp:
                continue

            content_type = resp.headers.get("Content-Type", "")
            soup = None
            forms = []
            links = []

            if "text/html" in content_type:
                try:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    links = self._extract_links(soup, url)
                    forms = self._extract_forms(soup, url)
                except Exception as e:
                    logger.debug(f"[Crawler] Parse error {url}: {e}")

            get_params = self._extract_get_params(url)

            page_record = {
                "url":          url,
                "method":       "GET",
                "status_code":  resp.status_code,
                "content_type": content_type,
                "params":       json.dumps(get_params),
                "forms":        forms,
                "depth":        depth,
                "response_text": resp.text[:5000],   # store first 5KB for analysis
            }
            self.crawled_pages.append(page_record)

            # Also add form endpoints as pages
            for form in forms:
                form_page = {
                    "url":          form["action_url"],
                    "method":       form["method"],
                    "status_code":  None,
                    "content_type": "",
                    "params":       json.dumps(form["inputs"]),
                    "forms":        [],
                    "depth":        depth + 1,
                    "response_text": "",
                }
                if form["action_url"] not in self.visited_urls and self._in_scope(form["action_url"]):
                    self.crawled_pages.append(form_page)
                    self.visited_urls.add(form["action_url"])

            # Enqueue newly discovered links
            for link in links:
                if link not in self.visited_urls:
                    self.visited_urls.add(link)
                    queue.append((link, depth + 1))

            time.sleep(0.1)   # polite delay between requests

        total = len(self.crawled_pages)
        self.progress_callback(f"=== Crawl Complete: {total} pages discovered ===")
        logger.info(f"[Crawler] Crawled {total} pages from {self.base_url}")
        return self.crawled_pages
