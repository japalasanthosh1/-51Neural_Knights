"""
Web Scanner — Tavily API search + deep page content fetching for PII analysis.
"""
import httpx
import asyncio
import logging
from bs4 import BeautifulSoup
from typing import List, Dict

logger = logging.getLogger(__name__)

TAVILY_API_KEY = "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"
TAVILY_SEARCH_URL = "https://api.tavily.com/search"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


class WebScanner:
    """Search the web via Tavily, fetch each page, extract text content."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or TAVILY_API_KEY

    async def search(self, query: str, max_results: int = 5) -> List[Dict]:
        """Search the web via Tavily API."""
        payload = {
            "api_key": self.api_key,
            "query": query,
            "max_results": min(max_results, 20),
            "search_depth": "advanced",
            "include_answer": True,
            "include_raw_content": True,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.post(TAVILY_SEARCH_URL, json=payload)
                if resp.status_code != 200:
                    return [{"error": f"Tavily API error {resp.status_code}"}]

                data = resp.json()
                results = []
                for item in data.get("results", [])[:max_results]:
                    results.append({
                        "url": item.get("url", ""),
                        "title": item.get("title", "Untitled"),
                        "snippet": item.get("content", ""),
                        "raw_content": item.get("raw_content", ""),
                        "score": item.get("score", 0),
                    })
                return results
            except httpx.TimeoutException:
                return [{"error": "Tavily search timed out"}]
            except Exception as e:
                return [{"error": f"Tavily error: {str(e)}"}]

    def _clean_html(self, html: str) -> str:
        """Helper to extract clean text from HTML."""
        if not html:
            return ""
        try:
            soup = BeautifulSoup(html, "html.parser")
            # Remove noise
            for tag in soup(["script", "style", "nav", "footer", "header", "aside", "noscript", "svg", "form"]):
                tag.decompose()
            
            # Extract text
            text = soup.get_text(separator="\n", strip=True)
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            return "\n".join(lines)
        except Exception as e:
            logger.error(f"HTML cleaning error: {e}")
            return ""

    async def fetch_page(self, url: str) -> str:
        """Fetch and extract clean text from a URL with improved handling."""
        is_social = any(d in url.lower() for d in ["linkedin.com", "github.com", "twitter.com", "x.com", "facebook.com", "instagram.com"])
        
        # Increased timeout for social media as they often take longer or involve redirects
        timeout = 20.0 if is_social else 15.0
        
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            try:
                # Add specific social media headers if needed
                headers = HEADERS.copy()
                if "linkedin.com" in url.lower():
                    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                    headers["Accept-Language"] = "en-US,en;q=0.5"
                
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    logger.warning(f"Failed to fetch {url}: {resp.status_code}")
                    return ""

                return self._clean_html(resp.text)[:50000]
            except Exception as e:
                logger.debug(f"Fetch error for {url}: {e}")
                return ""

    async def scan(self, query: str, engine, max_results: int = 5, log_fn=None) -> List[Dict]:
        """
        Full pipeline:
        1. Search web via Tavily
        2. Fetch each result page
        3. Run PII engine on content
        """
        if log_fn:
            log_fn(f"Initiating deep search: \"{query}\"")

        search_results = await self.search(query, max_results)
        valid = [r for r in search_results if "error" not in r]

        if log_fn:
            log_fn(f"Search complete. Analyzing {len(valid)} targets...")

        findings = []
        for i, sr in enumerate(search_results):
            if "error" in sr:
                findings.append({"error": sr["error"], "source": "web"})
                continue

            url = sr["url"]
            title = sr["title"]
            is_social = any(d in url.lower() for d in ["linkedin.com", "github.com", "twitter.com", "x.com"])

            if log_fn:
                domain_tag = "[SOCIAL]" if is_social else "[WEB]"
                log_fn(f"[{i+1}/{len(search_results)}] {domain_tag} {title[:50]}...")

            # Strategy: 
            # 1. Prefer Tavily's raw_content if it looks good
            # 2. Otherwise try deep fetch
            # 3. Fallback to snippet
            page_text = ""
            raw_content = sr.get("raw_content", "")
            
            if raw_content and len(raw_content) > 500:
                # If it's HTML, clean it, else use as is
                if "<html" in raw_content.lower() or "<body" in raw_content.lower():
                    page_text = self._clean_html(raw_content)
                else:
                    page_text = raw_content

            if not page_text or len(page_text) < 300:
                if log_fn: log_fn(f"  Fetching deep content for {url[:40]}...")
                page_text = await self.fetch_page(url)

            if not page_text:
                page_text = sr.get("snippet", "")

            if log_fn:
                log_fn(f"  Content: {len(page_text):,} chars")

            # Run PII detection
            pii_matches = engine.detect(page_text) if page_text else []

            # Count by detection method
            methods = {}
            for m in pii_matches:
                methods[m.detection_method] = methods.get(m.detection_method, 0) + 1

            result = {
                "source": "web",
                "url": url,
                "title": title,
                "content_length": len(page_text),
                "raw_content": page_text[:3000],
                "pii_count": len(pii_matches),
                "pii_findings": [
                    {
                        "type": m.pii_type,
                        "value": m.value,
                        "masked_value": m.masked_value,
                        "confidence": m.confidence,
                        "severity": m.severity,
                        "context": m.context,
                        "method": m.detection_method,
                    }
                    for m in pii_matches
                ],
                "detection_methods": methods,
            }
            findings.append(result)

            if pii_matches and log_fn:
                method_str = ", ".join(f"{k}:{v}" for k, v in methods.items())
                log_fn(f"  ⚠ {len(pii_matches)} PII found [{method_str}]")
            elif log_fn:
                log_fn(f"  ✓ Clean")

            await asyncio.sleep(0.2)

        return findings

    async def scan_url(self, url: str, engine, log_fn=None) -> Dict:
        """Scan a single URL for PII."""
        if log_fn:
            log_fn(f"Fetching: {url}")

        page_text = await self.fetch_page(url)
        title = url

        # Try to extract title from HTML
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(url, headers=HEADERS)
                soup = BeautifulSoup(r.text, "html.parser")
                title = soup.title.string.strip() if soup.title else url
        except Exception:
            pass

        if log_fn:
            log_fn(f"Content: {len(page_text):,} chars")

        pii_matches = engine.detect(page_text) if page_text else []

        methods = {}
        for m in pii_matches:
            methods[m.detection_method] = methods.get(m.detection_method, 0) + 1

        if log_fn:
            if pii_matches:
                method_str = ", ".join(f"{k}:{v}" for k, v in methods.items())
                log_fn(f"⚠ {len(pii_matches)} PII found [{method_str}]")
            else:
                log_fn(f"✓ Clean — no PII detected")

        return {
            "url": url,
            "title": title,
            "content_length": len(page_text),
            "raw_content": page_text[:3000],
            "pii_count": len(pii_matches),
            "pii_findings": [
                {
                    "type": m.pii_type,
                    "value": m.value,
                    "masked_value": m.masked_value,
                    "confidence": m.confidence,
                    "severity": m.severity,
                    "context": m.context,
                    "method": m.detection_method,
                }
                for m in pii_matches
            ],
            "detection_methods": methods,
        }
