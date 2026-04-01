THREAT_LANDSCAPE = [

    {
        "name": "Adversary-in-the-Middle Phishing (AiTM)",
        "category": "Identity Attack",
        "severity": "High",

        "description": "Attackers intercept authentication flows to steal session tokens and bypass MFA.",

        "common_indicators": [
            "Multiple MFA prompts (push fatigue)",
            "Login from new device immediately after user login",
            "Session reuse from different IP",
            "Lookalike domains"
        ],

        "signature_examples": [
            "Impossible travel login events",
            "User-agent mismatch between sessions",
            "Repeated MFA challenge logs"
        ],

        "mitre_mapping": [
            "T1566 - Phishing",
            "T1078 - Valid Accounts",
            "T1550 - Use of Stolen Session Tokens"
        ],

        "example_cves": [
            "CVE-2023-23397 (Outlook NTLM leak)",
        ],

        "pyramid_of_pain": {
            "level": "High",
            "why": "Behavior-based detection (session anomalies) forces attacker to change tactics, not just infrastructure."
        },

        "customer_risk": [
            "Account takeover",
            "Privilege escalation",
            "Access to sensitive systems"
        ]
    },

    {
        "name": "Credential Dumping",
        "category": "Credential Access",
        "severity": "High",

        "description": "Attackers extract credentials from memory or disk for reuse.",

        "common_indicators": [
            "LSASS access attempts",
            "Unusual process reading memory",
            "Credential reuse across hosts"
        ],

        "signature_examples": [
            "LSASS handle access",
            "Mimikatz detection rules",
            "Suspicious process injection"
        ],

        "mitre_mapping": [
            "T1003 - OS Credential Dumping"
        ],

        "example_cves": [
            "CVE-2021-36934 (HiveNightmare)",
        ],

        "pyramid_of_pain": {
            "level": "High",
            "why": "Requires attacker to change core technique if blocked."
        },

        "customer_risk": [
            "Lateral movement",
            "Privilege escalation",
            "Domain compromise"
        ]
    },

    {
        "name": "Ransomware Execution",
        "category": "Impact",
        "severity": "Critical",

        "description": "Encryption or disruption of systems to extort payment.",

        "common_indicators": [
            "Mass file changes",
            "High CPU usage from encryption",
            "Ransom note creation"
        ],

        "signature_examples": [
            "File entropy spikes",
            "Known ransomware file patterns",
            "Shadow copy deletion commands"
        ],

        "mitre_mapping": [
            "T1486 - Data Encrypted for Impact"
        ],

        "example_cves": [
            "CVE-2021-44228 (Log4Shell)",
        ],

        "pyramid_of_pain": {
            "level": "Medium",
            "why": "Blocking binaries is moderate pain, but behavior-based detection is stronger."
        },

        "customer_risk": [
            "Business outage",
            "Data loss",
            "Regulatory exposure"
        ]
    }

]
