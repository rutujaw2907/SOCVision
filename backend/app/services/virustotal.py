import os
import httpx
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses"


async def check_ip(ip: str):
    if not VT_API_KEY:
        return {
            "available": False,
            "error": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{VT_URL}/{ip}",
                headers=headers
            )

        if response.status_code == 404:
            return {
                "available": True,
                "ip": ip,
                "malicious": 0,
                "suspicious": 0,
                "reputation": 0
            }

        response.raise_for_status()

        data = response.json()
        attributes = data["data"]["attributes"]

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "available": True,
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get(
                "reputation",
                0
            )
        }

    except Exception as e:
        return {
            "available": False,
            "error": str(e)
        }