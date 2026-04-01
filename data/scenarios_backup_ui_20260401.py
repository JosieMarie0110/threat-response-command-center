SCENARIOS = {
    "Suspicious Login Activity": {
        "incident_snapshot": {
            "observed_activity": "Login detected from an unusual location using valid credentials.",
            "initial_concern": "Possible credential compromise or unauthorized access.",
            "attacker_objective": "Gain access using stolen, reused, or phished credentials.",
            "business_impact": "Potential unauthorized access to internal systems and sensitive data."
        },
        "signals": {
            "identity": [
                "Login from unusual geography",
                "Failed attempts followed by success"
            ],
            "endpoint": [
                "New device not previously associated with the user"
            ],
            "network": [
                "Suspicious outbound traffic after login"
            ],
            "cloud": [
                "Unexpected access to SaaS resources"
            ],
            "palo_alto": [
                "Cortex XDR flagged anomalous login behavior",
                "XSIAM correlated identity and endpoint signals"
            ]
        },
        "validation_thinking": [
            "Did the login actually succeed or was it only attempted?",
            "Is this geography normal for the user?",
            "Is the device known and managed?",
            "Was there follow-on activity after authentication?"
        ],
        "response_actions": {
            "immediate": [
                "Validate whether the login is legitimate",
                "Disable or challenge the account if risk is high",
                "Review active sessions and recent activity"
            ],
            "short_term": [
                "Reset credentials",
                "Revoke active sessions or tokens",
                "Review MFA enforcement for this user"
            ],
            "preventive": [
                "Enforce phishing-resistant MFA",
                "Tighten conditional access policies",
                "Review identity risk detections"
            ]
        },
        "customer_guidance": {
            "fear": {
                "what_it_looks_like": [
                    "Customer jumps to breach conclusions",
                    "Rapid escalation in tone",
                    "Repeated worst-case questions"
                ],
                "tam_response": [
                    "We are seeing suspicious activity, not confirmed compromise.",
                    "We are validating the signal before confirming impact."
                ],
                "questions_to_ask": [
                    "Is this location expected for the user?",
                    "Have you seen any confirmed follow-on activity yet?"
                ]
            }
        },
        "platform_value": [
            "Cortex correlation surfaced the risk early",
            "Without correlation, this may have looked like a normal login"
        ],
        "timeline": [
            "Login attempt observed from unusual location",
            "Authentication succeeds with valid credentials",
            "Additional activity appears inconsistent with normal behavior",
            "Validation begins across identity and endpoint telemetry",
            "Response actions are initiated"
        ]
    }
}
