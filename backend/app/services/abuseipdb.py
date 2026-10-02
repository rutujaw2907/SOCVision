import os

import httpx
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

ABUSEIPDB_URL = (
    "https://api.abuseipdb.com/api/v2/check"
)


async def check_ip(ip: str):
    if not ABUSEIPDB_API_KEY:
        return {
            "available": False,
            "error": "AbuseIPDB API key not configured",
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        async with httpx.AsyncClient(
            timeout=10
        ) as client:

            response = await client.get(
                ABUSEIPDB_URL,
                headers=headers,
                params=params,
            )

        response.raise_for_status()

        data = response.json().get(
            "data",
            {}
        )

        return {
            "available": True,
            "ip": data.get(
                "ipAddress",
                ip,
            ),
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore",
                0,
            ),
            "total_reports": data.get(
                "totalReports",
                0,
            ),
            "country_code": data.get(
                "countryCode"
            ),
            "country_name": data.get(
                "countryName"
            ),
            "isp": data.get(
                "isp"
            ),
            "domain": data.get(
                "domain"
            ),
            "usage_type": data.get(
                "usageType"
            ),
            "is_whitelisted": data.get(
                "isWhitelisted"
            ),
            "last_reported_at": data.get(
                "lastReportedAt"
            ),
        }

    except Exception as e:
        return {
            "available": False,
            "ip": ip,
            "error": str(e),
        }