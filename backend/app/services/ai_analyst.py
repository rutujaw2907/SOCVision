import json

import httpx


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

OLLAMA_MODEL = "llama3.2:3b"


SYSTEM_PROMPT = """
You are SOCVision AI Security Analyst.

Your job is to help a SOC analyst understand a detected security
incident.

Use ONLY the incident evidence supplied to you.

Do not invent:
- IP reputation
- attack evidence
- CVEs
- affected systems
- successful compromise
- attacker identity
- information that is not present in the evidence

Clearly distinguish between:
- observed evidence
- reasonable interpretation
- recommended investigation

Return a concise analyst report with these sections:

1. Incident Summary
2. Why It Was Detected
3. Attack Explanation
4. MITRE ATT&CK Context
5. Investigation Steps
6. Recommended Remediation

Use practical SOC terminology.
Keep recommendations actionable.
"""


async def analyze_incident(
    incident_data: dict
) -> dict:

    incident_json = json.dumps(
        incident_data,
        indent=2,
        default=str
    )

    prompt = f"""
{SYSTEM_PROMPT}

Analyze the following SOCVision security incident.

Incident data:

{incident_json}

Produce an analyst-oriented report using the required sections.

Do not claim that an attack succeeded unless the supplied evidence
supports that conclusion.
"""

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    try:
        async with httpx.AsyncClient(
            timeout=120
        ) as client:

            response = await client.post(
                OLLAMA_URL,
                json=payload
            )

        response.raise_for_status()

        data = response.json()

        analysis = data.get(
            "response",
            ""
        ).strip()

        if not analysis:
            return {
                "available": False,
                "error": (
                    "Ollama returned an empty analysis."
                )
            }

        return {
            "available": True,
            "model": OLLAMA_MODEL,
            "analysis": analysis
        }

    except httpx.ConnectError:
        return {
            "available": False,
            "error": (
                "Unable to connect to Ollama. "
                "Make sure the Ollama application "
                "is running on this computer."
            )
        }

    except httpx.HTTPStatusError as exc:
        return {
            "available": False,
            "error": (
                f"Ollama returned HTTP "
                f"{exc.response.status_code}."
            )
        }

    except Exception as exc:
        return {
            "available": False,
            "error": str(exc)
        }