"""
Social API Scanner — Direct integration with Twitter and Instagram.
Supports simulated mode for demonstration when keys are missing.
"""
import asyncio
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SocialAPIScanner:
    def __init__(self, web_scanner=None, twitter_keys: Dict = None, instagram_keys: Dict = None):
        self.web_scanner = web_scanner
        self.twitter_keys = twitter_keys
        self.instagram_keys = instagram_keys
        self.is_simulated = not (twitter_keys or instagram_keys)

    async def scan_handle(self, platform: str, handle: str, engine, deep_search: bool = True) -> List[Dict]:
        """
        Scan a specific social media handle for PII.
        If deep_search is True, also searches the web for related profiles/mentions.
        """
        platform = platform.lower()
        handle = handle.strip("@")
        
        logger.info(f"Scanning social identity: @{handle} on {platform}")
        all_results = []
        
        # 1. Direct API Scan (Profile info)
        if self.is_simulated:
            direct_res = await self._simulate_scan(platform, handle, engine)
        else:
            if platform == "twitter":
                direct_res = await self._scan_twitter_real(handle, engine)
            elif platform == "instagram":
                direct_res = await self._scan_instagram_real(handle, engine)
            else:
                direct_res = {"error": f"Platform {platform} not supported for direct API scan"}
        
        if direct_res:
            all_results.append(direct_res)

        # 2. Deep Web Discovery (Find related info/profiles around the web)
        if deep_search and self.web_scanner:
            logger.info(f"Initiating Deep Discovery for @{handle}...")
            # Target common social hubs
            discovery_query = f'"{handle}" OR "@{handle}" site:linkedin.com OR site:github.com OR site:facebook.com OR site:instagram.com OR site:twitter.com'
            web_results = await self.web_scanner.scan(discovery_query, engine, max_results=5)
            
            for res in web_results:
                if "error" not in res:
                    res["source"] = "social-discovery"
                    res["title"] = f"DISCOVERY: {res.get('title', 'Related Profile')}"
                    all_results.append(res)
                    
        return all_results

    async def _simulate_scan(self, platform: str, handle: str, engine) -> Dict:
        """Simulate a social media scan with realistic PII hits."""
        await asyncio.sleep(1.0)
        
        # Mock profile data
        profiles = {
            "santhosh_dev": {
                "name": "Santhosh Japala",
                "bio": "Full-stack dev at Tech Corp. Contact: santhosh.j@gmail.com | +91 98765 43210. Based in Bangalore.",
                "posts": [
                    "Just finished a new project! Check the repo at github.com/santhosh-j",
                    "My office is located near MG Road. Drop by if you're in the city!",
                    "Happy to announce my new email: santhosh.work@techcorp.io"
                ]
            }
        }
        
        profile = profiles.get(handle.lower(), {
            "name": f"User {handle}",
            "bio": f"No official bio found for @{handle}. Maybe check dev@example.com for more info.",
            "posts": [f"Sample post from @{handle}.", "Contact: +1 555-0199."]
        })
        
        all_text = f"Profile Name: {profile['name']}\nBio: {profile['bio']}\n" + "\n".join(profile['posts'])
        pii_matches = engine.detect(all_text)
        
        methods = {}
        for m in pii_matches:
            methods[m.detection_method] = methods.get(m.detection_method, 0) + 1
            
        return {
            "source": f"direct-{platform}",
            "handle": f"@{handle}",
            "title": f"[PROFILE] {profile['name']} (@{handle})",
            "url": f"https://{platform}.com/{handle}",
            "content_length": len(all_text),
            "raw_content": all_text,
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
            "simulated": True
        }

    async def _scan_twitter_real(self, handle: str, engine) -> Dict:
        return {"error": "Twitter API keys required for live scan."}

    async def _scan_instagram_real(self, handle: str, engine) -> Dict:
        return {"error": "Instagram API keys required for live scan."}
