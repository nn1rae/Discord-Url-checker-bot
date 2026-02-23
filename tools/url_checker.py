import asyncio
import aiohttp
from typing import Optional, Dict

class URLChecker:
    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.max_poll_attempts = 6
        self.poll_delay_seconds = 1

    async def check_url(self, url: str) -> Dict:
        if not self.api_key:
            return {
                "safe": True,
                "details": {"error": "VirusTotal API key not configured"},
                "checked": False,
            }

        headers = {"x-apikey": self.api_key}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/urls", headers=headers, data={"url": url}
                ) as response:
                    if response.status != 200:
                        return {
                            "safe": True,
                            "details": {"error": f"API error: {response.status}"},
                            "checked": False,
                        }

                    submit_data = await response.json()
                    analysis_id = submit_data["data"]["id"]

                for attempt in range(self.max_poll_attempts):
                    async with session.get(
                        f"{self.base_url}/analyses/{analysis_id}", headers=headers
                    ) as response:
                        if response.status != 200:
                            return {
                                "safe": True,
                                "details": {"error": f"Analysis error: {response.status}"},
                                "checked": False,
                            }

                        result = await response.json()
                        attributes = result["data"]["attributes"]
                        status = attributes.get("status")

                        if status == "completed":
                            stats = attributes["stats"]

                            malicious = stats.get("malicious", 0)
                            suspicious = stats.get("suspicious", 0)

                            is_safe = malicious == 0 and suspicious == 0

                            return {
                                "safe": is_safe,
                                "details": {
                                    "malicious": malicious,
                                    "suspicious": suspicious,
                                    "harmless": stats.get("harmless", 0),
                                    "undetected": stats.get("undetected", 0),
                                },
                                "checked": True,
                            }

                    if attempt < self.max_poll_attempts - 1:
                        await asyncio.sleep(self.poll_delay_seconds)

                return {
                    "safe": True,
                    "details": {
                        "error": "Analysis pending: VirusTotal did not finish in time"
                    },
                    "checked": False,
                }

        except Exception as e:
            print(f"Error checking URL: {e}")
            return {"safe": True, "details": {"error": str(e)}, "checked": False}
