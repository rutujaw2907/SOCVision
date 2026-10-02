MITRE_MAPPING = {
    "SQL Injection": {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application"
    },

    "Cross Site Scripting": {
        "technique": "T1189",
        "name": "Drive-by Compromise"
    },

    "Directory Traversal": {
        "technique": "T1006",
        "name": "Direct Volume Access"
    },

    "Sensitive Endpoint Access": {
        "technique": "T1087",
        "name": "Account Discovery"
    },

    "Brute Force": {
        "technique": "T1110",
        "name": "Brute Force"
    }
}


def map_to_mitre(attack_type):
    return MITRE_MAPPING.get(
        attack_type,
        {
            "technique": "Unknown",
            "name": "Unmapped Technique"
        }
    )