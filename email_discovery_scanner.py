"""
Email Discovery Scanner — Searches for social footprints and leakages via email.
"""
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class EmailDiscoveryScanner:
    def __init__(self, web_scanner):
        self.web_scanner = web_scanner

    async def scan_email(self, email: str, engine) -> List[Dict]:
        """
        Deep scan for an email address across the web.
        Finds associated profiles, breaches (mentions), and other PII.
        """
        email = email.lower().strip()
        logger.info(f"Initiating Email Identity Discovery for: {email}")
        
        # Targeted discovery query
        discovery_query = f'"{email}" OR "email: {email}" site:linkedin.com OR site:github.com OR site:facebook.com OR site:instagram.com OR site:pastebin.com OR site:twitter.com OR site:x.com'
        
        # Execute broad web search
        web_results = await self.web_scanner.scan(discovery_query, engine, max_results=7)
        
        all_results = []
        for res in web_results:
            if "error" not in res:
                res["source"] = "email-discovery"
                res["title"] = f"DISCOVERY: {res.get('title', 'Related Content')}"
                all_results.append(res)
                
        # If no results but it's a valid search, at least report the attempt
        if not all_results:
            logger.info(f"No public web associations found for {email}")
            
        return all_results
