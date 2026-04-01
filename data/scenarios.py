SCENARIOS = {
    "Suspicious Login from Foreign IP": {
        "incident_snapshot": {
            "observed_activity": "Multiple login attempts followed by a successful sign-in from an unusual foreign IP against a privileged user account.",
            "initial_concern": "This may indicate compromised credentials, session hijacking, or unauthorized access through a valid account.",
            "attacker_objective": "Gain trusted access through identity compromise, establish a foothold, and begin internal reconnaissance without triggering obvious malware-based detections.",
            "business_impact": "If access is valid and persistent, the attacker could reach sensitive systems, cloud resources, internal communications, or administrative functions.",
            "team_context": (
                "The team is seeing a pattern that begins like normal account abuse but has a higher-risk profile because the activity involves a privileged identity, an unusual geolocation, "
                "and timing that does not align with the user’s normal behavior. This is the kind of event that can look small at first because it uses legitimate authentication paths, "
                "but it may represent the earliest visible sign of a deeper identity-based intrusion. The team should be thinking about account ownership, MFA integrity, token reuse, "
                "adjacent sign-ins, impossible travel, and whether the access led to any additional actions after login."
            ),
            "objective_context": (
                "The likely attacker objective is not just to log in once. More often, this kind of access is used to blend in as a valid user, map the environment, review mail or cloud resources, "
                "identify privileged pathways, and quietly expand access. If the attacker is successful, they may pivot from identity compromise into persistence, privilege escalation, data access, "
                "or business email compromise without using obvious malware or loud network behavior."
            ),
        },
        "signals": {
            "identity": [
                "Successful sign-in follows multiple failed attempts from the same or nearby IP space.",
                "User geolocation and login time do not match normal access patterns.",
                "Privileged account shows an authentication path not commonly used by that user.",
            ],
            "endpoint": [
                "No matching local workstation activity observed for the user at the time of login.",
                "No recent endpoint evidence yet tying the session to a known managed device.",
                "Potential mismatch between device posture and access behavior.",
            ],
            "network": [
                "Source IP does not align with normal regional user traffic.",
                "Access may appear valid at the authentication layer while still being operationally suspicious.",
                "Follow-on connections should be checked for unusual destinations or admin portals.",
            ],
            "cloud": [
                "Cloud console or SaaS access after login may reveal whether the session progressed beyond authentication.",
                "New token issuance or unusual API activity may indicate session abuse.",
                "Mailbox, storage, or IAM access should be reviewed for early post-login actions.",
            ],
            "platform": [
                "Cross-domain correlation helps determine whether the login remained isolated or led to additional actions.",
                "Timeline stitching is valuable to connect sign-in, user behavior, and follow-on system interaction.",
            ],
        },
        "validation_thinking": [
            "Did the legitimate user confirm this sign-in, or does the user deny activity at that time and location?",
            "Was MFA satisfied normally, pushed repeatedly, bypassed, or inherited through an existing session?",
            "What happened in the minutes immediately after the successful login?",
            "Did the account access admin consoles, email, storage, IAM, or sensitive internal systems?",
            "Are there signs of token theft, browser session reuse, or impossible travel?",
            "Was this account targeted alone, or are there similar authentication patterns affecting other users?",
        ],
        "response_actions": {
            "immediate": [
                "Validate account ownership and current user status.",
                "Force sign-out and revoke active sessions or tokens if the activity is not legitimate.",
                "Temporarily restrict or step up access for the affected identity.",
                "Review immediate post-login activity for evidence of follow-on access.",
            ],
            "short_term": [
                "Reset credentials and re-register MFA if compromise is likely.",
                "Hunt for similar sign-in patterns across privileged and adjacent accounts.",
                "Review mailbox, SaaS, IAM, and cloud activity for attacker use of valid access.",
                "Confirm whether any persistence or forwarding rules were created.",
            ],
            "preventive": [
                "Harden privileged authentication requirements.",
                "Improve impossible-travel, suspicious-authentication, and token-abuse detections.",
                "Limit standing privilege and review conditional access policies.",
                "Reduce attack paths that rely only on valid credentials.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "This activity may represent valid-account misuse rather than malware-based compromise.",
                "A successful login is not automatically proof of full compromise, but it raises risk quickly when paired with unusual geography and privilege.",
                "The key question is what the session did after access was granted.",
            ],
            "validate_internally": [
                "Did the user confirm the activity?",
                "What sensitive systems or admin surfaces could this identity reach?",
                "Were any downstream actions taken after authentication?",
            ],
            "decisions": [
                "Whether to revoke access immediately or continue tightly scoped validation for a short period.",
                "Whether to trigger a broader identity review across privileged accounts.",
                "Whether executive or incident response stakeholders need to be engaged now.",
            ],
            "underestimating": [
                "Identity-based intrusions can remain quiet while still being highly damaging.",
                "An attacker using legitimate access can move farther than expected before endpoint controls trigger.",
                "Waiting too long can turn a simple access issue into broader business exposure.",
            ],
        },
        "customer_guidance": {
            "minimizing_the_signal": {
                "what_it_looks_like": [
                    "They focus on the fact that the login used the correct username and password.",
                    "They treat the event as low concern because no malware alert fired.",
                    "They assume it is probably travel or VPN-related without validation.",
                ],
                "tam_response": [
                    "Anchor the conversation around what happened after login, not just the authentication event itself.",
                    "Clarify that valid credentials can still represent unauthorized access.",
                    "Keep the room focused on evidence rather than assumptions.",
                ],
                "questions_to_ask": [
                    "Has the user confirmed this activity?",
                    "What did the account access after sign-in?",
                    "Do you see any similar authentication behavior elsewhere?",
                ],
            },
            "overwhelmed_by_uncertainty": {
                "what_it_looks_like": [
                    "They hesitate because they do not yet have full proof of compromise.",
                    "They avoid taking action while waiting for perfect certainty.",
                    "They worry about disrupting the user before they know more.",
                ],
                "tam_response": [
                    "Frame early containment as risk management, not overreaction.",
                    "Offer a sequence: validate ownership, review post-login activity, then decide on session revocation.",
                    "Reduce pressure by focusing on the next best step rather than the final conclusion.",
                ],
                "questions_to_ask": [
                    "What action would be reversible if taken now?",
                    "What additional evidence can be gathered in the next 15 minutes?",
                    "What is the downside of delaying containment?",
                ],
            },
        },
        "platform_value": [
            "Correlates authentication events with downstream activity to show whether the login stayed isolated or expanded.",
            "Helps quickly review identity, cloud, and access behavior in one workflow.",
            "Improves confidence in deciding whether the event is just suspicious or actively harmful.",
        ],
        "timeline": [
            "Account is targeted through password guessing, credential reuse, or previously stolen credentials.",
            "Attacker gains successful access using a valid authentication path.",
            "Session is used to test visibility, permissions, and reachable services.",
            "If not interrupted, attacker expands into mailbox, cloud resources, or privileged workflows.",
        ],
    },

    "Endpoint Beaconing to Unknown Domain": {
        "incident_snapshot": {
            "observed_activity": "A managed endpoint shows repeated outbound connections to an unknown domain on a periodic interval consistent with beaconing.",
            "initial_concern": "This may indicate command-and-control communication, malware callback activity, or a compromised application reaching external infrastructure.",
            "attacker_objective": "Maintain remote communication with the host, receive instructions, and preserve access for follow-on execution or data movement.",
            "business_impact": "If the host is compromised, the attacker may use it for persistence, lateral movement, credential access, or staged exfiltration.",
            "team_context": (
                "The team is seeing a host that appears to be reaching outward in a steady, repeated pattern that does not look like typical user-driven browsing. "
                "This kind of signal matters because periodic outbound traffic often reflects infrastructure waiting for instructions or reporting status back to an operator. "
                "The key question is whether the domain is benign-but-unknown, application-related, or evidence of active compromise tied to a process, user session, or malware family."
            ),
            "objective_context": (
                "The likely attacker objective is to preserve remote contact with the system while staying quiet. Beaconing often supports persistence and control: the attacker wants a way back in, "
                "a path to issue commands, and time to decide whether to expand access, collect credentials, stage payloads, or move laterally. Even when the traffic volume is small, the operational risk can be high."
            ),
        },
        "signals": {
            "endpoint": [
                "Repeated outbound connections occur on a predictable interval.",
                "Suspicious process, script host, or unsigned binary may be associated with the traffic.",
                "Parent-child process relationships may help distinguish malware from benign tooling.",
            ],
            "network": [
                "Unknown domain reputation or low-prevalence destination observed.",
                "Traffic cadence is more consistent than normal user browsing behavior.",
                "DNS and connection history may reveal related infrastructure or fallback domains.",
            ],
            "identity": [
                "Check whether the process ran in a standard user context or under elevated permissions.",
                "Review whether the device user recently executed unexpected files or scripts.",
            ],
            "cloud": [
                "Look for the same destination or indicators elsewhere across the environment.",
                "Confirm whether any cloud-hosted tooling or services legitimately use the domain.",
            ],
            "platform": [
                "Cross-telemetry review helps connect domain activity to process lineage and user context.",
                "Timeline correlation can show whether beaconing began after phishing, download, or remote execution.",
            ],
        },
        "validation_thinking": [
            "What process initiated the outbound communication?",
            "Is the destination known to any sanctioned business application or update service?",
            "Does the connection pattern persist across user inactivity or reboot cycles?",
            "Are there other hosts contacting the same domain or IP?",
            "Did the host show related script execution, suspicious downloads, or persistence activity?",
            "Is this host tied to a high-value user, admin workflow, or sensitive segment?",
        ],
        "response_actions": {
            "immediate": [
                "Contain or isolate the endpoint if compromise risk is high.",
                "Block the domain or IP after validating business impact.",
                "Capture process, network, and host context before destroying evidence.",
                "Review active sessions and any suspicious child processes.",
            ],
            "short_term": [
                "Hunt for the same indicator across other endpoints and network telemetry.",
                "Determine whether the beaconing is tied to malware, remote tooling, or a misclassified application.",
                "Review persistence, scheduled tasks, autoruns, and recent execution history.",
                "Check for credential access or lateral movement attempts from the host.",
            ],
            "preventive": [
                "Improve detection for low-and-slow outbound beaconing patterns.",
                "Strengthen allow-listing and unsigned binary controls.",
                "Harden email, download, and browser execution pathways.",
                "Tune detections to surface suspicious process-to-network relationships faster.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "Periodic outbound traffic can be more meaningful than a single connection because it suggests repeat communication.",
                "The priority is identifying the initiating process and whether the host is still under attacker control.",
                "Even if the domain is not confirmed malicious yet, the behavior pattern may justify containment.",
            ],
            "validate_internally": [
                "Does the domain belong to a sanctioned vendor or tool?",
                "Is the host associated with a critical user or business system?",
                "Are other hosts showing the same traffic pattern?",
            ],
            "decisions": [
                "Whether to isolate the device immediately.",
                "Whether to block the destination across the environment.",
                "Whether to widen investigation to a broader malware or phishing case.",
            ],
            "underestimating": [
                "Low-volume traffic can still support high-impact compromise.",
                "Attackers do not need noisy activity to maintain control of a host.",
                "A single affected system can become the starting point for broader spread.",
            ],
        },
        "customer_guidance": {
            "downplaying_low_volume_activity": {
                "what_it_looks_like": [
                    "They assume the traffic is too small to matter.",
                    "They focus on lack of visible disruption.",
                    "They want to wait because nothing appears broken.",
                ],
                "tam_response": [
                    "Clarify that beaconing is about control, not volume.",
                    "Keep the discussion focused on process lineage and repeat behavior.",
                    "Tie the signal to attacker access rather than bandwidth.",
                ],
                "questions_to_ask": [
                    "What process owns the communication?",
                    "How long has the pattern been present?",
                    "Do we see the same destination elsewhere?",
                ],
            },
            "hesitating_to_isolate": {
                "what_it_looks_like": [
                    "They worry about user disruption.",
                    "They want a perfect malware label before acting.",
                    "They stall because the destination is not yet conclusively malicious.",
                ],
                "tam_response": [
                    "Frame isolation as a temporary control while evidence is gathered.",
                    "Offer a stepwise approach so the action feels measured, not extreme.",
                    "Explain the cost of allowing confirmed beaconing to continue.",
                ],
                "questions_to_ask": [
                    "What is the business impact if the host remains online and compromised?",
                    "Can we isolate in a way that preserves evidence and reduces disruption?",
                    "What additional proof would materially change the decision?",
                ],
            },
        },
        "platform_value": [
            "Connects process activity, network communication, and timeline evidence in one place.",
            "Helps determine whether the domain event is isolated noise or part of a broader compromise path.",
            "Supports faster containment decisions by reducing investigation swivel-chairing.",
        ],
        "timeline": [
            "User or process executes content that establishes foothold or persistence.",
            "Endpoint begins periodic outbound communication to attacker-controlled or suspicious infrastructure.",
            "Attacker validates access and may issue follow-on commands.",
            "Compromised host is used for persistence, discovery, or expansion if not contained.",
        ],
    },

    "Data Exfiltration Spike": {
        "incident_snapshot": {
            "observed_activity": "A sharp increase in outbound data transfer is detected from a user or system to an unusual external destination.",
            "initial_concern": "This may indicate staged exfiltration, bulk collection, misuse of cloud storage, or unauthorized transfer of sensitive data.",
            "attacker_objective": "Remove valuable information from the environment for extortion, resale, leverage, or competitive advantage.",
            "business_impact": "If sensitive or regulated data is involved, the organization may face legal, operational, contractual, and reputational consequences.",
            "team_context": (
                "The team is seeing outbound movement that stands out in either size, destination, timing, or user context. This is important because exfiltration often happens late in an intrusion chain, "
                "after the attacker has already gained access and located valuable information. The team needs to determine whether the spike is legitimate business activity, negligent behavior, or deliberate removal of data."
            ),
            "objective_context": (
                "The likely attacker objective is to take information that creates leverage or long-term value. That could include customer records, intellectual property, credentials, internal documents, "
                "or regulated datasets. In many incidents, exfiltration is the monetization moment, which means the attacker may already have completed earlier stages such as reconnaissance and collection."
            ),
        },
        "signals": {
            "network": [
                "Outbound volume exceeds normal baseline for the user, host, or service.",
                "Destination is unusual, low-prevalence, or not normally associated with business workflows.",
                "Transfer timing may align with off-hours or reduced oversight.",
            ],
            "endpoint": [
                "Bulk file access, compression, archiving, or staging activity may precede transfer.",
                "Removable media, browser uploads, or sync tools may show supporting evidence.",
                "User activity may indicate mass file interaction before transfer.",
            ],
            "identity": [
                "Review whether the user recently elevated access or touched data outside normal scope.",
                "Compromised accounts may exfiltrate using the permissions of legitimate users.",
            ],
            "cloud": [
                "Cloud storage uploads, sharing changes, or large API-based exports may appear.",
                "New external collaborators or unusual storage targets should be reviewed.",
            ],
            "platform": [
                "Correlation across file access, user activity, and outbound transfer clarifies intent faster.",
                "Shared timeline context helps separate backup/admin activity from suspicious collection and removal.",
            ],
        },
        "validation_thinking": [
            "What data moved, from where, and to what destination?",
            "Does the transfer match any approved workflow, backup, sync job, or migration activity?",
            "Who initiated the transfer and under what identity or application context?",
            "Was there preceding collection, compression, or staging activity?",
            "Is the destination controlled, personal, partner-owned, or unknown?",
            "Do we have evidence this was deliberate, automated, compromised, or accidental?",
        ],
        "response_actions": {
            "immediate": [
                "Identify the destination and evaluate whether transfer is still active.",
                "Contain the user, host, or transfer path if exfiltration risk is high.",
                "Preserve evidence tied to file access, user behavior, and transfer metadata.",
                "Engage legal, privacy, or leadership stakeholders as appropriate.",
            ],
            "short_term": [
                "Determine data type, scope, and sensitivity.",
                "Review related user activity for collection and staging patterns.",
                "Hunt for additional transfer attempts, secondary destinations, or other involved identities.",
                "Assess whether this is isolated or part of a broader compromise.",
            ],
            "preventive": [
                "Improve controls around bulk movement, unusual destinations, and high-volume transfers.",
                "Strengthen data access governance and anomaly monitoring.",
                "Review how sensitive data is labeled, stored, and monitored.",
                "Tune detections around export, archive, and outbound data movement behaviors.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "The critical question is not only how much data moved, but what data it was.",
                "Exfiltration events can turn quickly into legal, privacy, or contractual issues.",
                "The team should validate scope before assuming the event is just an operational anomaly.",
            ],
            "validate_internally": [
                "Was the transfer business-approved?",
                "What sensitivity level applies to the data involved?",
                "Who owns the impacted dataset and downstream notification decisions?",
            ],
            "decisions": [
                "Whether to stop the transfer path immediately.",
                "Whether internal legal, privacy, or executive teams must be engaged now.",
                "Whether the event should be treated as confirmed incident response or heightened validation.",
            ],
            "underestimating": [
                "The importance of destination, sensitivity, and user context.",
                "How quickly notification obligations can arise once regulated data is confirmed.",
                "That attackers often exfiltrate only the most valuable subset, not the largest possible amount.",
            ],
        },
        "customer_guidance": {
            "focusing_only_on_transfer_size": {
                "what_it_looks_like": [
                    "They fixate on volume instead of data sensitivity.",
                    "They assume smaller transfers are harmless.",
                    "They delay because they have not yet seen a massive amount moved.",
                ],
                "tam_response": [
                    "Refocus the room on data type, ownership, and destination.",
                    "Clarify that a small transfer can still represent a major incident if the content is sensitive.",
                    "Keep the investigation centered on business consequence, not just transfer volume.",
                ],
                "questions_to_ask": [
                    "What specific data was involved?",
                    "Who owns that data internally?",
                    "Was the destination expected or approved?",
                ],
            },
            "avoiding_notification_discussion": {
                "what_it_looks_like": [
                    "They want to postpone legal or executive engagement.",
                    "They hesitate to classify the event because of downstream implications.",
                    "They worry about over-escalation.",
                ],
                "tam_response": [
                    "Frame stakeholder engagement as part of good incident governance, not as a final conclusion.",
                    "Encourage parallel validation so the organization is not caught late.",
                    "Reduce friction by clarifying that early notification internally does not equal external disclosure.",
                ],
                "questions_to_ask": [
                    "What data categories could trigger obligations?",
                    "Who needs early awareness if the event becomes confirmed?",
                    "What would be the cost of involving them too late?",
                ],
            },
        },
        "platform_value": [
            "Provides faster context around who moved data, where it went, and what else happened before the transfer.",
            "Helps correlate data movement with user behavior, system activity, and destination context.",
            "Supports cleaner escalation decisions when legal or business stakeholders need evidence quickly.",
        ],
        "timeline": [
            "Attacker or insider identifies valuable data.",
            "Data is collected, staged, or compressed for movement.",
            "Transfer begins to external storage, service, or infrastructure.",
            "If not interrupted, data leaves the environment and downstream impact expands.",
        ],
    },

    "Privilege Escalation Attempt": {
        "incident_snapshot": {
            "observed_activity": "A user, process, or service attempts to gain elevated permissions outside normal administrative behavior.",
            "initial_concern": "This may represent an attacker moving from initial access toward broader control of systems, accounts, or security tooling.",
            "attacker_objective": "Increase access in order to disable controls, move laterally, access sensitive systems, or establish stronger persistence.",
            "business_impact": "Successful privilege escalation can dramatically increase blast radius and reduce the organization’s ability to contain the intrusion quickly.",
            "team_context": (
                "The team is seeing activity that suggests someone or something is trying to move beyond its normal authority level. That shift matters because privilege escalation often changes the incident from a contained problem into an environment-wide risk. "
                "The investigation should determine whether this is expected admin behavior, a misconfiguration, or a deliberate attempt to obtain more control."
            ),
            "objective_context": (
                "The likely attacker objective is to gain the permissions needed to deepen the intrusion. With elevated access, an attacker can disable defenses, access protected systems, dump credentials, move between segments, or create durable persistence that is harder to remove."
            ),
        },
        "signals": {
            "identity": [
                "Unexpected admin group membership attempts or privilege assignment activity.",
                "Role changes or elevation requests outside normal workflow.",
                "Service accounts or users touching privileged surfaces they do not usually access.",
            ],
            "endpoint": [
                "Suspicious use of admin tools, token manipulation, or credential dumping utilities.",
                "Process execution may indicate attempts to bypass local permission boundaries.",
                "Security tooling tampering or disabled controls may appear.",
            ],
            "network": [
                "Access attempts to admin services, management ports, or sensitive segments increase.",
                "Lateral authentication activity may follow elevation attempts.",
            ],
            "cloud": [
                "IAM role modification, new access keys, or permission boundary changes may appear.",
                "Administrative API usage may spike after successful elevation.",
            ],
            "platform": [
                "Cross-surface correlation helps distinguish true escalation from legitimate admin work.",
                "Behavior context improves confidence around whether the attempt succeeded or merely occurred.",
            ],
        },
        "validation_thinking": [
            "Was the privilege escalation attempt successful or only attempted?",
            "What user, process, or service initiated the action?",
            "Does the activity align with a known admin workflow or change window?",
            "What systems, roles, or controls became reachable afterward?",
            "Do we see follow-on signs of defense evasion, credential dumping, or lateral movement?",
            "Was the activity isolated or part of a larger intrusion path?",
        ],
        "response_actions": {
            "immediate": [
                "Determine whether elevated access was obtained.",
                "Contain affected accounts, hosts, or tokens if compromise is likely.",
                "Protect security tooling and administrative control planes from tampering.",
                "Review immediate follow-on activity after the attempt.",
            ],
            "short_term": [
                "Audit role changes, permission grants, and admin access history.",
                "Hunt for related privilege abuse patterns across users, hosts, and cloud control planes.",
                "Validate whether controls were disabled or bypassed.",
                "Assess whether the escalation created additional persistence.",
            ],
            "preventive": [
                "Reduce standing privilege and improve privileged access governance.",
                "Increase monitoring of elevation pathways and sensitive admin actions.",
                "Segment critical administration surfaces and require stronger controls.",
                "Tune alerts around privilege changes tied to suspicious user or host behavior.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "Privilege escalation changes the severity of an event because it increases reach and impact potential.",
                "The team should determine whether elevation succeeded before assuming the issue is limited.",
                "Even attempted escalation can reveal attacker intent and next likely moves.",
            ],
            "validate_internally": [
                "Was there a legitimate admin task or change window in progress?",
                "Which systems or roles would become reachable if the escalation succeeded?",
                "Do we have follow-on activity that shows the new access was used?",
            ],
            "decisions": [
                "Whether to treat the event as active intrusion versus suspicious admin anomaly.",
                "Whether to lock down affected privileged pathways immediately.",
                "Whether to expand incident scope to include lateral movement and control plane review.",
            ],
            "underestimating": [
                "How quickly successful escalation can expand blast radius.",
                "That attempted escalation often precedes more damaging activity.",
                "The risk of waiting until control tampering or broader spread becomes visible.",
            ],
        },
        "customer_guidance": {
            "treating_it_as_admin_noise": {
                "what_it_looks_like": [
                    "They assume a role change or tool use is probably routine.",
                    "They downplay the event because privileged teams often generate noisy logs.",
                    "They want to wait for a clearer malicious indicator.",
                ],
                "tam_response": [
                    "Keep the conversation focused on success versus attempt and on follow-on activity.",
                    "Clarify that privilege-related signals deserve faster validation because of blast radius.",
                    "Help the room compare expected admin behavior against observed context.",
                ],
                "questions_to_ask": [
                    "Was there a legitimate administrative task underway?",
                    "Did the new permission get used afterward?",
                    "What would this actor be able to reach with elevated access?",
                ],
            },
            "avoiding_scope_expansion": {
                "what_it_looks_like": [
                    "They want to keep the incident narrowly defined.",
                    "They resist looking at related hosts, accounts, or control planes.",
                    "They are concerned about opening a broader investigation.",
                ],
                "tam_response": [
                    "Frame scope expansion as targeted validation, not uncontrolled escalation.",
                    "Explain that privilege events can be early indicators of broader compromise.",
                    "Guide them toward the most relevant adjacent checks first.",
                ],
                "questions_to_ask": [
                    "What are the nearest high-risk systems now reachable?",
                    "Which adjacent identities should be reviewed next?",
                    "What would make us confident this event is truly isolated?",
                ],
            },
        },
        "platform_value": [
            "Improves visibility into whether elevated access was attempted, achieved, and then used.",
            "Connects identity, host, and cloud control activity into one investigative path.",
            "Helps analysts explain why privilege-related events materially change incident severity.",
        ],
        "timeline": [
            "Initial foothold or misuse begins under limited permissions.",
            "Actor attempts to obtain broader rights or elevated execution.",
            "If successful, attacker expands access and weakens containment options.",
            "Broader movement, persistence, or control tampering follows unless interrupted.",
        ],
    },

    "Impossible Travel Login": {
        "incident_snapshot": {
            "observed_activity": "User logs in from two geographically distant locations within a short timeframe.",
            "initial_concern": "This may indicate compromised credentials being used from multiple locations or token/session abuse that makes the user appear present in impossible places.",
            "attacker_objective": "Gain persistent access using valid credentials while blending into normal activity and avoiding obvious malware-style detections.",
            "business_impact": "Unauthorized access to corporate systems may allow mailbox review, data access, SaaS abuse, or broader identity expansion.",
            "team_context": (
                "The team is seeing login activity that violates basic physical travel constraints. While VPN use or cloud routing can sometimes explain this, the pattern often points to compromised credentials, "
                "session reuse, or parallel access from attacker infrastructure. The team should focus on session overlap, post-login behavior, user confirmation, and whether the identity touched sensitive systems."
            ),
            "objective_context": (
                "The likely attacker objective is to maintain access as a seemingly legitimate user. This gives them a chance to quietly explore email, cloud apps, file repositories, and admin pathways while avoiding "
                "noisy endpoint behaviors. Impossible-travel-style activity can be an early warning that valid-account abuse is already underway."
            ),
        },
        "signals": {
            "identity": [
                "Login from geographically distant locations within a timeframe inconsistent with real travel.",
                "Multiple active sessions may overlap.",
                "Authentication patterns differ from normal user behavior.",
            ],
            "endpoint": [
                "No matching endpoint activity supports one of the sessions.",
                "Device history may not align with the new access origin.",
            ],
            "network": [
                "Different IP ranges or regions appear close together in time.",
                "One location may map to infrastructure the user has never used before.",
            ],
            "cloud": [
                "Parallel SaaS access sessions may be present.",
                "New application access may follow one of the sign-ins.",
            ],
            "platform": [
                "Cross-correlation helps determine whether the event is a routing quirk or true parallel access.",
            ],
        },
        "validation_thinking": [
            "Was the user traveling, on VPN, or using a mobile carrier route that could explain the pattern?",
            "Are both sessions still active?",
            "What actions occurred after each login?",
            "Did one of the locations access systems the user normally does not touch?",
            "Are similar patterns occurring for other users?",
        ],
        "response_actions": {
            "immediate": [
                "Confirm whether the user initiated either session.",
                "Revoke active sessions if access cannot be explained.",
                "Reset credentials if suspicious activity is confirmed.",
                "Review recent post-login activity across affected apps and systems.",
            ],
            "short_term": [
                "Assess whether mailbox, SaaS, or cloud control activity followed the sign-ins.",
                "Check for token theft, new OAuth consent, or suspicious session creation.",
                "Review whether other identities show the same pattern.",
            ],
            "preventive": [
                "Improve impossible-travel logic with user, device, and session context.",
                "Use stronger conditional access and session controls.",
                "Reduce persistence opportunities tied to stolen sessions or long-lived tokens.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "Impossible travel is often less about travel and more about whether the identity was accessed from multiple places at once.",
                "The key question is whether the sign-ins led to meaningful follow-on activity.",
                "This can be an early sign of valid-account compromise.",
            ],
            "validate_internally": [
                "Did the user confirm the activity?",
                "Were both locations expected in any way?",
                "What systems were accessed from each session?",
            ],
            "decisions": [
                "Whether to revoke sessions immediately.",
                "Whether to treat this as isolated authentication risk or broader account compromise.",
                "Whether to widen review to adjacent identities or applications.",
            ],
            "underestimating": [
                "How much damage can occur through valid-account misuse without malware.",
                "The possibility that one location reflects attacker access even if another is legitimate.",
                "How quickly mailbox, file, or admin access can follow a compromised session.",
            ],
        },
        "customer_guidance": {
            "assuming_it_is_just_vpn_noise": {
                "what_it_looks_like": [
                    "They dismiss the alert as normal VPN behavior immediately.",
                    "They avoid checking what happened after login.",
                    "They assume impossible travel is always noisy but harmless.",
                ],
                "tam_response": [
                    "Acknowledge that routing can create noise, but keep the focus on post-login actions and session overlap.",
                    "Help the team separate explanation from confirmation.",
                    "Push for evidence instead of default dismissal.",
                ],
                "questions_to_ask": [
                    "What did each session do after authentication?",
                    "Do device and app histories support both locations?",
                    "Has the user confirmed the activity?",
                ],
            }
        },
        "platform_value": [
            "Correlates geographic anomalies with downstream app and session activity.",
            "Helps distinguish travel-related noise from real valid-account abuse.",
            "Provides faster context for whether the alert stayed informational or became actionable.",
        ],
        "timeline": [
            "Credentials or session access become available to attacker.",
            "Parallel or near-parallel sign-ins occur from incompatible locations.",
            "Attacker tests access and begins using the account like a normal user.",
            "If not interrupted, follow-on access extends into email, SaaS, or privileged paths.",
        ],
    },

    "MFA Fatigue Attack": {
        "incident_snapshot": {
            "observed_activity": "User receives repeated MFA push notifications followed by an eventual approval.",
            "initial_concern": "This may indicate MFA fatigue, push bombing, or an attacker attempting to wear down the user into approving an unauthorized request.",
            "attacker_objective": "Bypass MFA by exploiting user confusion, annoyance, or urgency rather than breaking the authentication control directly.",
            "business_impact": "If successful, the attacker gains valid session access and may immediately begin using the account to access email, SaaS, cloud resources, or sensitive workflows.",
            "team_context": (
                "The team is seeing repeated authentication attempts that escalate into a successful approval. This pattern matters because it shifts the problem from purely technical authentication to identity compromise through human pressure. "
                "The team should focus on whether the user knowingly approved the request, what happened after approval, and whether similar targeting is underway against other users."
            ),
            "objective_context": (
                "The likely attacker objective is to turn already-stolen credentials into a real session by overwhelming the user into approving MFA. Once access is granted, the attacker can behave as a legitimate user and move into email, SaaS, or cloud workflows without triggering the same skepticism as malware-based activity."
            ),
        },
        "signals": {
            "identity": [
                "Multiple MFA push attempts occur within a short period.",
                "An eventual approval follows repeated denial or ignored prompts.",
                "The source of the login may be unusual for the user.",
            ],
            "endpoint": [
                "No corresponding local user activity is visible at the time of authentication.",
                "No user-driven application launch aligns with the successful session.",
            ],
            "network": [
                "Authentication may originate from unfamiliar IP space or geography.",
            ],
            "cloud": [
                "A new session is established after the MFA approval.",
                "Cloud or SaaS access may follow quickly if the approval was malicious.",
            ],
            "platform": [
                "Correlation between repeated prompts and successful sign-in helps identify fatigue-style attacks.",
            ],
        },
        "validation_thinking": [
            "Did the user knowingly approve the MFA request?",
            "Was the login expected at that time?",
            "What actions occurred after the successful approval?",
            "Did the account access email, SaaS, or cloud consoles shortly afterward?",
            "Are repeated MFA attempts affecting other users?",
        ],
        "response_actions": {
            "immediate": [
                "Confirm whether the user intentionally approved the request.",
                "Revoke active session if the approval was not legitimate.",
                "Reset credentials and review MFA posture if suspicious.",
                "Block or challenge suspicious login sources when appropriate.",
            ],
            "short_term": [
                "Review post-login activity to determine how the session was used.",
                "Check for related sign-in anomalies across other users.",
                "Assess whether the attacker used the session for mailbox, SaaS, or administrative access.",
            ],
            "preventive": [
                "Implement MFA fatigue protections such as number matching or stronger approval context.",
                "Educate users on repeated push abuse and safe denial behavior.",
                "Reduce opportunities for attackers to repeatedly prompt users without stronger risk-based controls.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "MFA does not remove risk if a user is pressured into approving a malicious request.",
                "This is a human-targeted identity event, not just an authentication anomaly.",
                "The critical question is what happened after approval.",
            ],
            "validate_internally": [
                "Did the user intend to approve the request?",
                "Did the session access anything sensitive?",
                "Are similar patterns visible across other identities?",
            ],
            "decisions": [
                "Whether to reset the account immediately.",
                "Whether to widen investigation to broader identity targeting.",
                "Whether to reinforce user-facing controls or communication right away.",
            ],
            "underestimating": [
                "How easily strong MFA can be undermined through human pressure.",
                "That attackers may already have the user’s password before the push campaign begins.",
                "How fast follow-on activity can begin once the session is approved.",
            ],
        },
        "customer_guidance": {
            "treating_the_approval_as_user_error_only": {
                "what_it_looks_like": [
                    "They blame the user and stop investigating the rest of the event.",
                    "They focus only on awareness training instead of session activity.",
                    "They treat the issue as resolved once the user is contacted.",
                ],
                "tam_response": [
                    "Acknowledge the user action, but keep the focus on whether the attacker actually used the session.",
                    "Frame this as both a control and response problem, not only a training issue.",
                    "Keep the room anchored to evidence after the approval.",
                ],
                "questions_to_ask": [
                    "What happened immediately after approval?",
                    "Was any sensitive application or mailbox accessed?",
                    "Did the same source target other users?",
                ],
            }
        },
        "platform_value": [
            "Surfaces repeated MFA attempts and correlates them to successful access.",
            "Helps separate accidental user behavior from targeted authentication abuse.",
            "Improves the speed of response once a malicious approval becomes visible.",
        ],
        "timeline": [
            "Attacker obtains valid credentials.",
            "Repeated MFA prompts are sent to the targeted user.",
            "User eventually approves a request under pressure or confusion.",
            "Attacker establishes a real session and begins follow-on access.",
        ],
    },

    "Business Email Compromise (BEC)": {
        "incident_snapshot": {
            "observed_activity": "A user account sends unusual financial, vendor-related, or executive-style emails that do not match normal communication patterns.",
            "initial_concern": "This may indicate business email compromise, mailbox abuse, or a compromised account being used for fraud or sensitive information requests.",
            "attacker_objective": "Exploit trust relationships to trigger payments, redirect funds, harvest sensitive information, or create downstream fraud opportunities.",
            "business_impact": "Financial loss, reputational damage, trust erosion, and possible external stakeholder impact can occur quickly once fraudulent emails are sent.",
            "team_context": (
                "The team is seeing outbound communication that deviates from normal user behavior and may involve urgency, authority, or payment language. This matters because BEC often succeeds not through malware but through trust exploitation. "
                "The investigation should focus on whether the user sent the messages, whether mailbox rules or forwarding changes exist, and whether recipients have already acted on the content."
            ),
            "objective_context": (
                "The likely attacker objective is to use the compromised identity as a trusted communication channel. That can support fraudulent payment requests, vendor changes, internal data harvesting, or longer-term monitoring of conversations to strike at the most advantageous moment."
            ),
        },
        "signals": {
            "identity": [
                "Login from unusual location or unfamiliar session context may precede email activity.",
                "Mailbox access patterns may differ from the user’s norm.",
            ],
            "endpoint": [
                "No corresponding user endpoint activity may align with the time emails were sent.",
            ],
            "network": [
                "Emails may target unusual recipients or financial contacts unexpectedly.",
            ],
            "cloud": [
                "Mailbox rules may be created or modified.",
                "Forwarding behavior or hidden monitoring may be present.",
                "Unusual message access or sent-item activity may appear.",
            ],
            "platform": [
                "Correlation across login, mailbox changes, and outbound communication helps determine whether the account was weaponized.",
            ],
        },
        "validation_thinking": [
            "Did the user actually send the emails?",
            "Were mailbox rules changed, forwarding enabled, or sent items manipulated?",
            "Were there login anomalies before the communication began?",
            "Did recipients act on any requests already?",
            "Are other mailboxes showing similar signs of compromise?",
        ],
        "response_actions": {
            "immediate": [
                "Disable or restrict the account if compromise is likely.",
                "Remove malicious mailbox or forwarding rules.",
                "Notify affected recipients not to act on recent requests.",
                "Reset credentials and revoke active sessions.",
            ],
            "short_term": [
                "Audit mailbox access, sent items, and message traces.",
                "Check whether sensitive conversations or attachments were accessed.",
                "Assess whether other identities were targeted or compromised similarly.",
            ],
            "preventive": [
                "Strengthen phishing-resistant MFA and mailbox monitoring.",
                "Improve detection around rule creation, forwarding, and anomalous communication patterns.",
                "Reinforce finance and vendor verification controls outside of email.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "This may already involve external communication impact, not just internal account risk.",
                "Speed matters because recipients may act before the technical investigation finishes.",
                "BEC often succeeds by exploiting trust rather than causing visible disruption.",
            ],
            "validate_internally": [
                "Which messages were sent and to whom?",
                "Did any include financial instructions, sensitive requests, or urgency language?",
                "Has anyone already acted on the messages?",
            ],
            "decisions": [
                "Whether to notify finance, legal, or external parties immediately.",
                "Whether to widen review to vendor, executive, or adjacent mailbox risk.",
                "Whether to trigger full incident response based on external impact potential.",
            ],
            "underestimating": [
                "How quickly fraudulent communications can create real financial loss.",
                "The importance of mailbox rule review and silent monitoring behaviors.",
                "That the attacker may have already read sensitive communications before sending anything.",
            ],
        },
        "customer_guidance": {
            "focusing_only_on_the_sent_email": {
                "what_it_looks_like": [
                    "They focus only on the fraudulent message itself.",
                    "They overlook mailbox forwarding or prior monitoring activity.",
                    "They assume the damage begins only when an email is sent.",
                ],
                "tam_response": [
                    "Broaden the view from the email itself to the full mailbox access story.",
                    "Keep attention on what the attacker may have observed before acting.",
                    "Help the room connect login, mailbox rules, and downstream recipient impact.",
                ],
                "questions_to_ask": [
                    "Were mailbox rules or forwarding settings changed?",
                    "Did the attacker monitor prior conversations before sending the email?",
                    "Have any recipients already responded or acted?",
                ],
            }
        },
        "platform_value": [
            "Correlates identity activity, mailbox manipulation, and suspicious outbound communication.",
            "Improves visibility into silent mailbox abuse that may precede obvious fraud.",
            "Supports faster response when external stakeholders may already be impacted.",
        ],
        "timeline": [
            "Attacker gains access to the mailbox or identity.",
            "Mailbox is monitored, altered, or prepared for fraud.",
            "Fraudulent or deceptive messages are sent to trusted recipients.",
            "If not interrupted, financial loss or sensitive exposure may occur quickly.",
        ],
    },

    "Malicious PowerShell Execution": {
        "incident_snapshot": {
            "observed_activity": "Encoded or obfuscated PowerShell command executes on an endpoint from a parent process or user context that does not align with expected administrative activity.",
            "initial_concern": "This may indicate attacker use of native tooling for execution, download activity, persistence setup, reconnaissance, or payload delivery.",
            "attacker_objective": "Leverage trusted built-in tooling to execute malicious commands while reducing the visibility of traditional dropped malware.",
            "business_impact": "If the execution is malicious, the host may become a staging point for persistence, credential theft, lateral movement, or broader compromise.",
            "team_context": (
                "The team is seeing command-line behavior that deviates from normal administrative or user activity. PowerShell events deserve extra attention because the tooling is legitimate, flexible, and often used by attackers to avoid dropping obvious binaries. "
                "The key is to understand what launched the command, what the command did, and whether any follow-on network or persistence behavior emerged."
            ),
            "objective_context": (
                "The likely attacker objective is to use a native execution mechanism that blends into the operating system. That can support downloading additional content, executing scripts in memory, collecting system information, disabling defenses, or creating persistence without relying on a conventional malware file."
            ),
        },
        "signals": {
            "endpoint": [
                "Encoded, obfuscated, or hidden-window PowerShell execution is observed.",
                "Parent-child process relationship does not align with normal admin tooling or user workflow.",
                "Command-line arguments suggest download, execution, or defense evasion activity.",
            ],
            "identity": [
                "The process runs under a user context that may not normally execute scripts.",
                "The account involved may not be associated with administrative scripting activity.",
            ],
            "network": [
                "Outbound connection or follow-on domain access may occur after the script runs.",
                "Execution may immediately precede beaconing or suspicious downloads.",
            ],
            "cloud": [
                "If the script touches cloud or SaaS APIs, follow-on access may extend beyond the endpoint.",
            ],
            "platform": [
                "Correlation between script execution, process lineage, and network activity helps determine whether the event is benign automation or attacker execution.",
            ],
        },
        "validation_thinking": [
            "Was the script expected administrative activity or user-driven automation?",
            "What exactly did the command attempt to do?",
            "What process launched the PowerShell instance?",
            "Did network traffic, downloads, persistence, or credential access follow?",
            "Is the same pattern present on other endpoints?",
        ],
        "response_actions": {
            "immediate": [
                "Contain or isolate the endpoint if malicious execution is likely.",
                "Capture process lineage, command details, and host context before cleanup.",
                "Terminate suspicious execution if it is still active.",
                "Review recent network activity associated with the process.",
            ],
            "short_term": [
                "Decode and analyze the command content.",
                "Review autoruns, scheduled tasks, services, and other persistence mechanisms.",
                "Search for the same command pattern or parent-child relationship elsewhere.",
                "Assess whether the script accessed credentials, tokens, or sensitive files.",
            ],
            "preventive": [
                "Restrict PowerShell where practical and improve logging coverage.",
                "Improve detections around obfuscation, suspicious arguments, and unusual parent processes.",
                "Strengthen controls around script execution paths and administrative tooling.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "Built-in tools can be abused in ways that look more legitimate than malware.",
                "The meaning of the event depends heavily on process context and command content.",
                "This is often an execution-stage signal that can lead to broader compromise quickly.",
            ],
            "validate_internally": [
                "Was there any expected scripting or admin automation running?",
                "What process and user launched the command?",
                "Did the event lead to downloads, persistence, or outbound traffic?",
            ],
            "decisions": [
                "Whether to isolate the endpoint immediately.",
                "Whether to widen investigation to a campaign or one-host event.",
                "Whether to treat the activity as confirmed malicious execution or suspicious-but-unresolved scripting.",
            ],
            "underestimating": [
                "How often attackers use built-in tools to stay under the radar.",
                "The importance of process lineage and immediate network context.",
                "That malicious execution may be the beginning of a longer attack path, not the full story.",
            ],
        },
        "customer_guidance": {
            "assuming_all_powershell_is_admin_noise": {
                "what_it_looks_like": [
                    "They dismiss the event because PowerShell is common in Windows environments.",
                    "They do not review parent process context or command content.",
                    "They assume legitimate tools cannot be part of real compromise.",
                ],
                "tam_response": [
                    "Keep the focus on behavior, not the tool name alone.",
                    "Differentiate normal admin scripting from obfuscated or unusual execution context.",
                    "Guide the room toward process lineage and post-execution evidence.",
                ],
                "questions_to_ask": [
                    "Who or what launched the command?",
                    "Was the script expected in this context?",
                    "What happened immediately after execution?",
                ],
            }
        },
        "platform_value": [
            "Improves visibility into script execution context, not just process names.",
            "Helps correlate endpoint execution with network or downstream activity.",
            "Reduces the chance of dismissing attacker behavior as routine tooling noise.",
        ],
        "timeline": [
            "Initial foothold or user action creates an opportunity for execution.",
            "PowerShell is used to run commands, scripts, or downloads.",
            "Attacker uses the execution path to establish persistence, gather information, or call out.",
            "If not interrupted, the endpoint becomes a launch point for broader actions.",
        ],
    },

    "Admin Role Assignment": {
        "incident_snapshot": {
            "observed_activity": "A user, identity, or service account is granted administrative privileges or elevated cloud permissions outside normal workflow expectations.",
            "initial_concern": "This may represent unauthorized privilege escalation, risky delegation, or a compromised identity expanding access.",
            "attacker_objective": "Gain elevated rights to control systems, weaken defenses, access sensitive resources, or create durable administrative persistence.",
            "business_impact": "Unauthorized administrative access can dramatically increase blast radius and reduce the organization’s ability to contain further activity quickly.",
            "team_context": (
                "The team is seeing a privilege change that materially increases access scope. This matters because once elevated permissions are granted, the actor can often move faster than defenders, reach more systems, and disable or weaken controls. "
                "The team should determine whether the role assignment was approved, whether it was used, and whether any downstream administrative actions followed."
            ),
            "objective_context": (
                "The likely attacker objective is to turn an initial foothold into durable administrative control. With elevated privileges, an attacker can move into control planes, cloud resources, identity systems, and sensitive administration paths that are harder to monitor and more damaging to lose."
            ),
        },
        "signals": {
            "identity": [
                "Unexpected admin group membership or privileged role assignment appears.",
                "Role change does not align with normal approval path or change timing.",
                "Service or user account receives elevated rights not normally associated with its role.",
            ],
            "cloud": [
                "Permissions, role bindings, or entitlements are updated.",
                "Administrative APIs may become accessible immediately after the change.",
            ],
            "platform": [
                "Role assignment and follow-on usage can be correlated to show whether the change was merely logged or actively exploited.",
            ],
        },
        "validation_thinking": [
            "Was the role assignment approved and expected?",
            "Who initiated the change and from what session context?",
            "Did the newly elevated identity use the privileges afterward?",
            "Were security controls, IAM settings, or sensitive resources touched after the change?",
            "Are similar elevation patterns affecting other identities?",
        ],
        "response_actions": {
            "immediate": [
                "Revoke or suspend unauthorized elevated access.",
                "Review immediate actions taken after the privilege assignment.",
                "Protect nearby administrative surfaces from further misuse.",
                "Contain the account if compromise is likely.",
            ],
            "short_term": [
                "Audit all recent role and permission changes.",
                "Review whether the elevated rights enabled persistence or control changes.",
                "Search for related privilege modifications across identities and cloud control paths.",
            ],
            "preventive": [
                "Strengthen approval workflows around privileged assignments.",
                "Reduce standing admin access and improve just-in-time access controls.",
                "Improve detections around role changes followed by sensitive actions.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "Unauthorized administrative access changes the severity of the incident quickly.",
                "The real risk depends on whether the rights were used after assignment.",
                "Even brief administrative access can create persistence or downstream exposure.",
            ],
            "validate_internally": [
                "Was there a legitimate change request or approval?",
                "What became reachable after the assignment?",
                "Did the identity use the new privileges?",
            ],
            "decisions": [
                "Whether to treat the event as confirmed privilege abuse.",
                "Whether to widen the incident into broader control-plane review.",
                "Whether to restrict adjacent administrative paths proactively.",
            ],
            "underestimating": [
                "How fast control can expand once admin rights are granted.",
                "That attacker value comes from what the new access enables next.",
                "The risk of assuming the change was harmless because it was quickly spotted.",
            ],
        },
        "customer_guidance": {
            "assuming_role_change_equals_low_risk_until_used": {
                "what_it_looks_like": [
                    "They downplay the event because the assignment alone did not cause an outage.",
                    "They delay reviewing follow-on administrative actions.",
                    "They treat it as a permissions housekeeping issue.",
                ],
                "tam_response": [
                    "Keep focus on what the new access made possible, not only the role assignment itself.",
                    "Frame elevated access as a severity multiplier.",
                    "Guide the team to check immediate downstream usage first.",
                ],
                "questions_to_ask": [
                    "What did the identity access after the role change?",
                    "Did any security controls or privileged settings change next?",
                    "Was the assignment approved through normal process?",
                ],
            }
        },
        "platform_value": [
            "Improves visibility into risky role changes and their immediate consequences.",
            "Connects permission assignments to follow-on control activity.",
            "Helps explain why privilege changes require faster validation than standard user events.",
        ],
        "timeline": [
            "Actor gains initial foothold or existing access.",
            "Elevated role or privilege is assigned outside normal workflow.",
            "New access is tested and used to expand control.",
            "If not interrupted, broader administrative impact follows.",
        ],
    },

    "DNS Tunneling Behavior": {
        "incident_snapshot": {
            "observed_activity": "A host generates a high volume of DNS queries with unusual length, structure, or periodicity that differs from normal name resolution behavior.",
            "initial_concern": "This may indicate DNS tunneling, covert command-and-control, or data exfiltration using DNS as a stealth channel.",
            "attacker_objective": "Use DNS as a covert communication path to move data or maintain contact while blending into a protocol that is widely allowed and often under-scrutinized.",
            "business_impact": "If the traffic reflects active tunneling, the environment may already be experiencing silent data loss or command-and-control activity from a compromised system.",
            "team_context": (
                "The team is seeing DNS behavior that does not look like standard application or user resolution patterns. This matters because DNS is both essential and widely trusted, making it attractive to attackers who want a quiet channel for communication or exfiltration. "
                "The investigation should focus on the host involved, the queried domains, the structure of the requests, and whether the activity aligns with any sanctioned software."
            ),
            "objective_context": (
                "The likely attacker objective is to maintain a low-visibility channel that can support outbound signaling or exfiltration without relying on obviously malicious ports or traffic patterns. DNS tunneling often indicates the attacker wants stealth, persistence, and enough time to move information out quietly."
            ),
        },
        "signals": {
            "network": [
                "High frequency DNS requests from a single host or small set of hosts.",
                "Unusually long or patterned subdomains suggest encoded content.",
                "Request cadence looks more automated than normal browsing or application behavior.",
            ],
            "endpoint": [
                "A specific host or process may be generating the requests repeatedly.",
                "Compromised process activity may coincide with the unusual DNS volume.",
            ],
            "identity": [
                "Review whether the host or user has any reason to communicate with the observed domains.",
            ],
            "cloud": [
                "The same domains or indicators may appear in other environments if tunneling is widespread.",
            ],
            "platform": [
                "Correlation of host, domain, and timing context helps distinguish malware tunneling from unusual-but-legitimate software behavior.",
            ],
        },
        "validation_thinking": [
            "Are the queried domains legitimate or associated with a known sanctioned service?",
            "What host and process are generating the traffic?",
            "Do the query names suggest encoded or structured data?",
            "Is the same pattern visible on multiple hosts?",
            "Did the activity begin after another suspicious event such as phishing or script execution?",
        ],
        "response_actions": {
            "immediate": [
                "Block or sinkhole suspicious domains if impact allows.",
                "Isolate the host if compromise risk is high.",
                "Preserve DNS, process, and host context before cleanup.",
                "Review whether any data may already have been transmitted.",
            ],
            "short_term": [
                "Analyze DNS logs for encoded patterns or repeated structures.",
                "Determine whether the activity came from malware, a tool, or sanctioned software.",
                "Search for the same destination or behavior across the environment.",
            ],
            "preventive": [
                "Improve DNS anomaly detection and query inspection.",
                "Reduce blind trust in outbound DNS paths.",
                "Tune detections for unusual query structure, volume, and host concentration.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "DNS can be abused as a covert channel even though it is a normal protocol.",
                "This kind of activity may reflect either quiet control or silent exfiltration.",
                "The host context matters just as much as the domain itself.",
            ],
            "validate_internally": [
                "Does any sanctioned application use this behavior?",
                "What host and process are responsible?",
                "Is the same activity happening elsewhere?",
            ],
            "decisions": [
                "Whether to block the domains immediately.",
                "Whether to isolate the affected host.",
                "Whether to treat this as confirmed compromise or suspicious network behavior pending deeper analysis.",
            ],
            "underestimating": [
                "How stealthy DNS-based channels can be.",
                "That small, repetitive queries may still carry meaningful data or control instructions.",
                "How long this type of activity can persist if treated as harmless noise.",
            ],
        },
        "customer_guidance": {
            "assuming_dns_means_benign": {
                "what_it_looks_like": [
                    "They trust the protocol because it is required for normal operations.",
                    "They hesitate because the domain is not yet conclusively malicious.",
                    "They focus only on blocking without understanding host context.",
                ],
                "tam_response": [
                    "Reframe the conversation from protocol trust to behavior trust.",
                    "Keep attention on the pattern, process, and host, not just the existence of DNS traffic.",
                    "Help the team validate whether the behavior is truly normal for that system.",
                ],
                "questions_to_ask": [
                    "What host and process generated the traffic?",
                    "Does the domain pattern suggest encoding or automation?",
                    "Is any sanctioned software known to behave this way?",
                ],
            }
        },
        "platform_value": [
            "Detects DNS anomalies that would otherwise blend into normal infrastructure traffic.",
            "Improves confidence when distinguishing covert communication from legitimate application behavior.",
            "Helps tie DNS evidence back to host and process context for response decisions.",
        ],
        "timeline": [
            "Host is compromised or controlled by attacker.",
            "DNS channel is established for signaling or exfiltration.",
            "Repeated DNS requests carry data or command instructions.",
            "If not interrupted, the channel supports ongoing stealthy compromise.",
        ],
    },

    "Mass SaaS File Download": {
        "incident_snapshot": {
            "observed_activity": "A user or service account downloads an unusually large number of files from a SaaS platform within a short period.",
            "initial_concern": "This may indicate bulk data collection, insider misuse, account compromise, or staged exfiltration through a trusted cloud application.",
            "attacker_objective": "Extract valuable business information using a normal collaboration platform to reduce suspicion and avoid traditional perimeter controls.",
            "business_impact": "Sensitive or regulated information may be exposed, creating legal, contractual, operational, or reputational consequences.",
            "team_context": (
                "The team is seeing volume-based activity that stands out from normal SaaS usage. This matters because collaboration platforms are trusted, familiar, and often rich with sensitive information. "
                "The key questions are whether the user intended the activity, what data was involved, and whether this represents normal project work, negligent misuse, insider risk, or attacker-driven collection."
            ),
            "objective_context": (
                "The likely attacker objective is to move quickly through a trusted platform and collect high-value data without looking like classic malware-driven exfiltration. By using SaaS platforms, the attacker can blend into routine user behavior while still extracting valuable documents at scale."
            ),
        },
        "signals": {
            "cloud": [
                "Large spike in file downloads or exports from a SaaS platform.",
                "Sensitive folders, shared drives, or restricted repositories are accessed unusually quickly.",
                "Download timing or sequence differs from normal user behavior.",
            ],
            "identity": [
                "Single user or service account is responsible for the activity.",
                "The account may be touching data outside its typical business scope.",
            ],
            "endpoint": [
                "The user endpoint may show corresponding browser, sync, or storage activity.",
            ],
            "network": [
                "Follow-on transfer, archive, or synchronization behavior may appear after the downloads.",
            ],
            "platform": [
                "Correlating user identity, file access, and time-based volume helps determine whether the activity is routine or risky.",
            ],
        },
        "validation_thinking": [
            "Was this expected project or administrative activity?",
            "What data was downloaded and how sensitive is it?",
            "Is the account owner aware of the activity?",
            "Did the same account perform related sharing, sync, or export behavior?",
            "Did the downloads lead to any secondary transfer or storage activity?",
        ],
        "response_actions": {
            "immediate": [
                "Assess whether the account should be paused or restricted.",
                "Review the file set involved and identify the highest-risk data first.",
                "Preserve evidence around who accessed what and when.",
                "Contain the account if compromise risk is high.",
            ],
            "short_term": [
                "Audit file access and export history in the SaaS platform.",
                "Review endpoint and network context for secondary movement of the downloaded data.",
                "Assess whether related identities or shared repositories were also touched.",
            ],
            "preventive": [
                "Improve DLP, download anomaly monitoring, and sensitive repository controls.",
                "Review how high-value data is segmented and monitored within SaaS platforms.",
                "Tune alerts around unusual volume, speed, and cross-scope access behaviors.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "Large SaaS download activity can be as meaningful as classic exfiltration alerts.",
                "The most important questions are what data moved and whether the activity was expected.",
                "This may reflect legitimate work, insider misuse, or attacker use of a trusted platform.",
            ],
            "validate_internally": [
                "Did the user intend to download this data?",
                "What sensitivity level applies to the file set?",
                "Did the data move anywhere else afterward?",
            ],
            "decisions": [
                "Whether to restrict the account immediately.",
                "Whether to escalate based on the data involved.",
                "Whether to widen scope into broader insider-risk or compromised-account review.",
            ],
            "underestimating": [
                "How effective SaaS platforms are for quiet data collection.",
                "That attacker-driven collection may look similar to legitimate collaboration at first.",
                "The importance of what data was accessed over the simple fact that files were downloaded.",
            ],
        },
        "customer_guidance": {
            "assuming_cloud_activity_is_less_serious": {
                "what_it_looks_like": [
                    "They treat SaaS downloads as lower risk than network exfiltration.",
                    "They assume collaboration tools make the activity inherently normal.",
                    "They focus on volume only and ignore sensitivity.",
                ],
                "tam_response": [
                    "Keep the room focused on the content involved, not just the platform used.",
                    "Clarify that trusted apps can still be the channel for meaningful loss.",
                    "Anchor the conversation to scope, intent, and downstream movement.",
                ],
                "questions_to_ask": [
                    "What kind of data was downloaded?",
                    "Was the user expected to access this material?",
                    "Do we see any secondary transfer after the download?",
                ],
            }
        },
        "platform_value": [
            "Highlights abnormal cloud download behavior tied to a specific identity and repository set.",
            "Improves context around whether activity is routine collaboration or high-risk collection.",
            "Supports faster data-scope decisions when cloud platforms are involved.",
        ],
        "timeline": [
            "User or attacker gains access to valuable SaaS content.",
            "Bulk file access or export activity begins.",
            "Data is downloaded from trusted cloud repositories.",
            "If not interrupted, the downloaded content may be staged, shared, or exfiltrated further.",
        ],
    },

    "Ransomware Precursor Activity": {
        "incident_snapshot": {
            "observed_activity": "A host shows suspicious process execution, rapid file access behavior, and system activity consistent with ransomware staging rather than completed encryption.",
            "initial_concern": "This may represent a pre-impact phase where an attacker is preparing for encryption, disruption, or broader destructive action.",
            "attacker_objective": "Position the environment for maximum operational impact by identifying reachable systems, disabling defenses, and preparing files or tooling for encryption.",
            "business_impact": "If the activity progresses, the organization may face service disruption, data loss, business outage, and high-pressure response conditions.",
            "team_context": (
                "The team is seeing behaviors that often show up before full ransomware impact. That matters because the best opportunity to reduce damage is usually before encryption begins, not after. "
                "The team should focus on whether this is truly staging, whether multiple hosts are involved, and whether backup, security, or administrative systems are being targeted."
            ),
            "objective_context": (
                "The likely attacker objective is not only to encrypt files but to shape the environment so encryption has the highest possible blast radius. That can include disabling controls, moving laterally, staging tooling, identifying backups, and preparing the victim for extortion leverage."
            ),
        },
        "signals": {
            "endpoint": [
                "Rapid file access, process anomalies, or suspicious tooling appears on the host.",
                "Behavior may resemble enumeration, staging, or pre-encryption preparation.",
                "Security tools or local controls may be tampered with or disabled.",
            ],
            "network": [
                "Lateral activity or administrative communications may increase before impact.",
            ],
            "identity": [
                "Privileged or service accounts may be used to expand access or disable protections.",
            ],
            "cloud": [
                "Cloud backups, storage, or administrative paths may also be assessed or targeted.",
            ],
            "platform": [
                "Cross-host and timeline visibility helps determine whether the activity is isolated staging or the beginning of multi-host impact.",
            ],
        },
        "validation_thinking": [
            "Is encryption already underway or is this still precursor activity?",
            "Are multiple hosts or administrative systems involved?",
            "Do we see signs of defense evasion, backup targeting, or credential misuse?",
            "What processes and users are associated with the behavior?",
            "Is this tied to known tooling or adversary tradecraft?",
        ],
        "response_actions": {
            "immediate": [
                "Isolate affected host or hosts if ransomware staging is likely.",
                "Protect backups, security tooling, and administrative control paths immediately.",
                "Preserve evidence around processes, sessions, and lateral movement indicators.",
                "Assess whether encryption or destructive activity has already begun elsewhere.",
            ],
            "short_term": [
                "Hunt for the same behavior on additional hosts.",
                "Review account misuse, lateral movement, and defense tampering.",
                "Assess whether staging included backup targeting or persistence.",
            ],
            "preventive": [
                "Improve detections for pre-encryption behaviors and impact staging.",
                "Reduce standing privilege and strengthen segmentation around backup and admin systems.",
                "Harden response paths for fast host isolation and backup protection.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "This may be the narrow window before full ransomware impact.",
                "Fast containment decisions often matter more than perfect labeling at this stage.",
                "The event may already involve multiple hosts even if only one alert surfaced first.",
            ],
            "validate_internally": [
                "Are any backups, admin systems, or security controls being touched?",
                "Do we see the same behavior elsewhere?",
                "Is encryption already visible anywhere in the environment?",
            ],
            "decisions": [
                "Whether to isolate only one host or broader segments immediately.",
                "Whether to activate full incident response and business continuity stakeholders now.",
                "Whether to prioritize backup protection over narrower investigation steps.",
            ],
            "underestimating": [
                "How fast ransomware campaigns move once staging is complete.",
                "That precursor activity is often the last meaningful chance to reduce impact.",
                "The importance of protecting backups and admin paths immediately.",
            ],
        },
        "customer_guidance": {
            "waiting_for_encryption_to_be_sure": {
                "what_it_looks_like": [
                    "They want visible encryption before escalating.",
                    "They treat precursor alerts as too early to act on.",
                    "They hesitate because the impact phase is not yet obvious.",
                ],
                "tam_response": [
                    "Reframe the situation as a prevention window, not a false alarm problem.",
                    "Encourage evidence-driven containment before the environment moves into visible impact.",
                    "Keep focus on protecting the most critical assets first.",
                ],
                "questions_to_ask": [
                    "Do we see backup or admin system targeting?",
                    "Has the same behavior appeared on other hosts?",
                    "What is the cost of waiting until encryption is visible?",
                ],
            }
        },
        "platform_value": [
            "Helps surface pre-impact ransomware behavior before encryption becomes widespread.",
            "Supports cross-host review of staging and lateral spread.",
            "Improves confidence in containment decisions during the most time-sensitive phase.",
        ],
        "timeline": [
            "Initial access and foothold are established.",
            "Attacker stages tools, enumerates environment, and weakens defenses.",
            "Pre-impact behaviors increase across hosts or admin paths.",
            "If not interrupted, encryption or destructive impact follows.",
        ],
    },

    "OAuth App Consent Abuse": {
        "incident_snapshot": {
            "observed_activity": "A user grants consent to a new OAuth application that requests broad access to mailbox, files, or other cloud resources.",
            "initial_concern": "This may indicate malicious OAuth consent abuse, allowing persistent access without requiring repeated credential theft.",
            "attacker_objective": "Gain durable application-level access to user data and cloud resources through delegated permissions that survive beyond a single login event.",
            "business_impact": "Sensitive data may be exposed through a trusted application path, creating ongoing access risk even if the user’s password is later changed.",
            "team_context": (
                "The team is seeing an application trust event rather than only a user login event. This matters because malicious OAuth abuse can create persistence and data access through a consented app, which may not behave like a classic compromised session. "
                "The investigation should focus on what permissions were granted, whether the app is legitimate, and what resources were accessed afterward."
            ),
            "objective_context": (
                "The likely attacker objective is to bypass repeated login friction by obtaining delegated access through an application. Once consent exists, the attacker can often continue reading mail, accessing files, or interacting with cloud data through the app until the grant is removed."
            ),
        },
        "signals": {
            "cloud": [
                "A new OAuth or cloud app consent event appears.",
                "The requested permissions may be broader than expected for normal business use.",
                "The application may be new, low-prevalence, or unknown to the organization.",
            ],
            "identity": [
                "User account is tied to the consent event.",
                "Consent may follow phishing, credential use, or suspicious user interaction.",
            ],
            "platform": [
                "Correlating app consent with subsequent mailbox, file, or API access helps determine whether the app was weaponized.",
            ],
        },
        "validation_thinking": [
            "Did the user knowingly approve the app?",
            "Is the application sanctioned or expected?",
            "What permissions were granted?",
            "Did the app access mailbox, files, or sensitive resources afterward?",
            "Are other users granting consent to the same app?",
        ],
        "response_actions": {
            "immediate": [
                "Revoke the malicious or suspicious app consent.",
                "Assess whether the user account should also be reset or session-revoked.",
                "Review what resources the app accessed before removal.",
                "Check whether other users consented to the same application.",
            ],
            "short_term": [
                "Audit cloud and API activity associated with the application.",
                "Determine whether the consent came via phishing or social engineering.",
                "Review whether the app created further persistence or data exposure paths.",
            ],
            "preventive": [
                "Tighten app consent policies and admin approval requirements.",
                "Improve user awareness around malicious app consent prompts.",
                "Monitor for broad or unusual permission requests across users.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "Password reset alone may not resolve the issue if app consent remains active.",
                "The real risk depends on what the app was allowed to access and whether it already used those permissions.",
                "This is a cloud trust problem as much as an identity problem.",
            ],
            "validate_internally": [
                "Is the application approved or recognized?",
                "What permissions were granted?",
                "Did the app access or export any sensitive resources?",
            ],
            "decisions": [
                "Whether to revoke consent immediately across the tenant.",
                "Whether to widen investigation to phishing or broader user targeting.",
                "Whether the event requires data exposure review based on accessed content.",
            ],
            "underestimating": [
                "How persistent OAuth abuse can be compared with a simple session compromise.",
                "That the application may continue to access data without repeated user interaction.",
                "The importance of reviewing what permissions were actually granted.",
            ],
        },
        "customer_guidance": {
            "treating_it_like_a_simple_login_issue": {
                "what_it_looks_like": [
                    "They focus only on user password change.",
                    "They overlook the consent grant itself.",
                    "They assume the problem ends when the user logs out.",
                ],
                "tam_response": [
                    "Shift the room from user session thinking to application permission thinking.",
                    "Clarify that the app may retain access even if the user’s password changes.",
                    "Keep focus on the permission scope and downstream resource access.",
                ],
                "questions_to_ask": [
                    "What permissions did the app receive?",
                    "Was the app used after consent?",
                    "Did other users grant the same app access?",
                ],
            }
        },
        "platform_value": [
            "Improves visibility into risky cloud app consent behavior.",
            "Connects app authorization events to actual mailbox, file, or API access.",
            "Helps teams avoid under-scoping app-based persistence events.",
        ],
        "timeline": [
            "User is tricked or prompted into consenting to an application.",
            "Application gains delegated access to cloud resources.",
            "Attacker uses the app path to access data or maintain persistence.",
            "If not interrupted, the application continues accessing resources quietly.",
        ],
    },

    "Lateral Movement via SMB": {
        "incident_snapshot": {
            "observed_activity": "A host begins making unusual SMB connections or file-sharing access attempts across multiple internal systems in a pattern inconsistent with its normal role.",
            "initial_concern": "This may indicate lateral movement, reconnaissance, credential reuse, or attacker expansion from an initial foothold.",
            "attacker_objective": "Move from one compromised system to additional hosts in order to expand access, identify valuable systems, and increase operational reach.",
            "business_impact": "If successful, the attacker can widen the incident beyond the initial host, increase blast radius, and position the environment for ransomware, credential theft, or deeper compromise.",
            "team_context": (
                "The team is seeing east-west movement behavior that suggests the affected host is no longer acting only within its expected role. This matters because lateral movement often marks the point where a localized incident begins to become an environment-wide problem. "
                "The investigation should determine whether the SMB behavior is administrative, automated, or a sign of attacker expansion."
            ),
            "objective_context": (
                "The likely attacker objective is to expand beyond the initial foothold and identify systems worth targeting next. SMB-based movement can support discovery, credential reuse, file staging, or access to systems that provide more privilege or higher operational value."
            ),
        },
        "signals": {
            "network": [
                "SMB traffic increases toward hosts not normally accessed by the source system.",
                "Connection spread suggests broad scanning, probing, or movement rather than a single business workflow.",
            ],
            "endpoint": [
                "Processes associated with remote access, file copy, or administrative execution may appear.",
                "The source host may show signs of credential reuse or remote task execution.",
            ],
            "identity": [
                "The activity may use privileged, reused, or stolen credentials.",
                "Accounts involved may not normally touch the targeted systems.",
            ],
            "platform": [
                "Correlating host, identity, and time-based movement patterns helps distinguish legitimate administration from attacker spread.",
            ],
        },
        "validation_thinking": [
            "Is the SMB traffic part of a known admin workflow, deployment, or backup job?",
            "What account is being used for the movement?",
            "What systems are being targeted and why do they matter?",
            "Did the source host recently show signs of compromise?",
            "Are remote execution, file copy, or credential misuse also visible?",
        ],
        "response_actions": {
            "immediate": [
                "Contain the source host if lateral movement is likely.",
                "Restrict or monitor the account being used for the movement.",
                "Protect nearby high-value systems from further spread.",
                "Capture evidence around process, credential, and remote access activity.",
            ],
            "short_term": [
                "Map the set of targeted hosts and systems reached.",
                "Determine whether access succeeded or was only attempted.",
                "Review whether the movement led to persistence or additional compromise on new hosts.",
            ],
            "preventive": [
                "Strengthen segmentation and reduce unnecessary east-west access.",
                "Reduce standing admin credentials and improve credential hygiene.",
                "Tune detections for unusual SMB fan-out, role-inconsistent access, and remote execution behaviors.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "This may represent the moment the incident expands from one host to many.",
                "The main question is whether the movement succeeded, not only whether attempts occurred.",
                "Host-to-host spread often changes the urgency and scope of response.",
            ],
            "validate_internally": [
                "Was there a legitimate administrative reason for this pattern?",
                "Which systems were reached or attempted?",
                "What credentials were involved?",
            ],
            "decisions": [
                "Whether to isolate the source host immediately.",
                "Whether to widen containment to adjacent systems or accounts.",
                "Whether to escalate incident scope based on confirmed spread.",
            ],
            "underestimating": [
                "How quickly lateral movement can increase blast radius.",
                "The importance of verifying whether access succeeded on downstream hosts.",
                "That the initial host may no longer be the main risk once spread begins.",
            ],
        },
        "customer_guidance": {
            "treating_it_as_normal_internal_noise": {
                "what_it_looks_like": [
                    "They assume internal SMB traffic is routine by default.",
                    "They focus on volume rather than destination relevance.",
                    "They delay because no downstream host is visibly impacted yet.",
                ],
                "tam_response": [
                    "Shift the discussion from protocol familiarity to access pattern abnormality.",
                    "Keep focus on the source host, credential context, and target set.",
                    "Help the team determine whether the access aligns with real operational workflows.",
                ],
                "questions_to_ask": [
                    "Does this host normally communicate with these systems over SMB?",
                    "What account is being used for the movement?",
                    "Did any downstream system show successful access or follow-on execution?",
                ],
            }
        },
        "platform_value": [
            "Connects internal movement patterns to the host and identity that initiated them.",
            "Improves speed when separating administrative noise from attacker spread.",
            "Supports earlier scope expansion decisions before multi-host impact becomes obvious.",
        ],
        "timeline": [
            "Initial host is compromised.",
            "Attacker begins probing or accessing additional internal systems over SMB.",
            "Movement expands into reachable hosts using available credentials or access.",
            "If not interrupted, downstream hosts become part of the compromise path.",
        ],
    },

    "Mailbox Rule Manipulation": {
        "incident_snapshot": {
            "observed_activity": "A mailbox rule or forwarding behavior is created, changed, or hidden in a way that does not match the user’s typical email configuration.",
            "initial_concern": "This may indicate mailbox compromise, silent monitoring, or preparation for fraud, data theft, or communication hijacking.",
            "attacker_objective": "Gain visibility into sensitive communications, hide malicious activity, or redirect information to support fraud or persistence.",
            "business_impact": "Sensitive conversations, attachments, and trust-based workflows may be exposed without the user realizing their mailbox is being monitored.",
            "team_context": (
                "The team is seeing a mailbox configuration change that may not create immediate disruption but can materially increase attacker visibility and control. This matters because mailbox rules are often used quietly before a more visible fraud or exfiltration stage. "
                "The investigation should focus on whether the rule was authorized, what it forwarded or hid, and whether other mailbox changes occurred at the same time."
            ),
            "objective_context": (
                "The likely attacker objective is to create silent access to communications and position the mailbox for future abuse. That may support business email compromise, invoice fraud, internal surveillance, or continued persistence even if the user notices nothing unusual day to day."
            ),
        },
        "signals": {
            "cloud": [
                "A new forwarding, deletion, move, or hide rule is created.",
                "Mailbox settings differ from normal user patterns.",
                "Other mailbox changes may accompany the rule creation.",
            ],
            "identity": [
                "Login anomalies may precede the configuration change.",
                "The account may have been accessed from an unusual session or location.",
            ],
            "platform": [
                "Correlating access anomalies with mailbox changes helps determine whether the rule is part of active compromise.",
            ],
        },
        "validation_thinking": [
            "Did the user knowingly create the rule?",
            "What messages, senders, or folders are affected by it?",
            "Does the rule forward, hide, or delete messages?",
            "Were there suspicious logins before the change?",
            "Do other mailboxes show similar behavior?",
        ],
        "response_actions": {
            "immediate": [
                "Remove unauthorized mailbox rules or forwarding settings.",
                "Revoke active sessions if mailbox compromise is likely.",
                "Reset account credentials and review MFA posture if needed.",
                "Assess whether sensitive communications were exposed or redirected.",
            ],
            "short_term": [
                "Review mailbox access history and message traces.",
                "Check for related mailbox, forwarding, or delegated-access changes.",
                "Hunt for the same behavior across additional user accounts.",
            ],
            "preventive": [
                "Improve detections around mailbox rule creation and hidden forwarding behavior.",
                "Strengthen mailbox monitoring for user and admin changes.",
                "Reduce the opportunity for silent persistence in cloud mail platforms.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "Mailbox rules are often quiet indicators of active compromise, not harmless user customization.",
                "The risk comes from what the attacker can observe or redirect through the mailbox.",
                "This event can be an early or silent stage of larger fraud or data theft.",
            ],
            "validate_internally": [
                "Did the user create the rule knowingly?",
                "What messages were affected?",
                "Were any sensitive conversations exposed or forwarded externally?",
            ],
            "decisions": [
                "Whether to treat the account as confirmed compromised.",
                "Whether to notify affected recipients or internal stakeholders.",
                "Whether to widen review to related mailboxes or communications.",
            ],
            "underestimating": [
                "How long mailbox rules can persist unnoticed.",
                "The value of silent email monitoring to attackers.",
                "That mailbox changes may matter even when no fraudulent email has been sent yet.",
            ],
        },
        "customer_guidance": {
            "seeing_it_as_only_a_mail_setting": {
                "what_it_looks_like": [
                    "They view the rule as harmless unless fraud is already visible.",
                    "They focus only on deleting the rule without reviewing mailbox history.",
                    "They treat it as user error until proven otherwise.",
                ],
                "tam_response": [
                    "Reframe the rule as a potential persistence and visibility mechanism.",
                    "Guide the room from mailbox settings toward attacker intent and exposure scope.",
                    "Keep focus on what the rule allowed or hid before removal.",
                ],
                "questions_to_ask": [
                    "What messages did the rule forward, hide, or delete?",
                    "When was the rule created relative to suspicious access?",
                    "Do other mailboxes show similar manipulation?",
                ],
            }
        },
        "platform_value": [
            "Improves visibility into mailbox manipulations that often precede larger fraud or data exposure.",
            "Correlates mailbox changes with identity and session anomalies.",
            "Helps teams avoid under-scoping quiet but high-value mailbox abuse.",
        ],
        "timeline": [
            "Attacker gains mailbox or identity access.",
            "Mailbox rules or forwarding changes are created to support monitoring or deception.",
            "Attacker uses the mailbox for visibility, hiding, or fraud enablement.",
            "If not interrupted, sensitive communications or trust workflows are exploited.",
        ],
    },

    "Suspicious API Key Creation": {
        "incident_snapshot": {
            "observed_activity": "A new API key, token, or access credential is created and then used shortly afterward in a context that does not align with normal automation patterns.",
            "initial_concern": "This may indicate unauthorized machine-level access, persistence creation, or attacker preparation for continued cloud or application access outside of normal user sessions.",
            "attacker_objective": "Create durable access that persists beyond a single login and can be used programmatically to access resources quietly over time.",
            "business_impact": "If unauthorized, the key may enable persistent access to sensitive services, cloud resources, data stores, or automation workflows without obvious user interaction.",
            "team_context": (
                "The team is seeing an access mechanism created for automation rather than human use. This matters because API keys can quietly outlast sessions and are often harder to notice once in use. "
                "The investigation should focus on whether the key creation was expected, who or what created it, what permissions it has, and how it was used afterward."
            ),
            "objective_context": (
                "The likely attacker objective is to establish programmatic persistence that is less dependent on repeated logins or user interaction. Once a key exists, the attacker can often continue accessing resources in a way that looks like normal automation unless the behavior is closely reviewed."
            ),
        },
        "signals": {
            "cloud": [
                "A new API key, token, or service credential is generated unexpectedly.",
                "The credential is used soon after creation.",
                "Permission scope or usage pattern may exceed normal automation behavior.",
            ],
            "identity": [
                "The creating account may not normally create machine credentials.",
                "Creation may follow suspicious login or privilege activity.",
            ],
            "platform": [
                "Correlating key creation with immediate use helps distinguish planned automation from malicious persistence.",
            ],
        },
        "validation_thinking": [
            "Was the key creation expected as part of a real deployment or operational change?",
            "Who created the key and from what session context?",
            "What permissions does the key have?",
            "What resources did it access after creation?",
            "Are there other keys or service credentials showing similar patterns?",
        ],
        "response_actions": {
            "immediate": [
                "Revoke the suspicious API key or token if unauthorized.",
                "Review the identity and session that created it.",
                "Assess what resources the credential accessed before revocation.",
                "Contain the creating account if compromise is likely.",
            ],
            "short_term": [
                "Audit recent credential creation events across the environment.",
                "Determine whether the key was used for persistence, export, or control actions.",
                "Review whether related cloud permissions or roles also changed.",
            ],
            "preventive": [
                "Tighten controls around API key creation and approval.",
                "Reduce long-lived machine credentials where possible.",
                "Monitor for keys created outside expected automation paths or immediately used in unusual ways.",
            ],
        },
        "customer_decisions": {
            "need_to_know": [
                "API keys can create persistence that survives beyond a user session.",
                "The critical question is what the key could access and what it already did.",
                "Machine credentials deserve the same urgency as suspicious logins when they are unexpected.",
            ],
            "validate_internally": [
                "Was the key part of a known deployment or integration?",
                "What services or data did it touch?",
                "What permissions were granted to it?",
            ],
            "decisions": [
                "Whether to revoke the credential immediately.",
                "Whether to widen the event into broader cloud persistence review.",
                "Whether the creating account should also be treated as compromised.",
            ],
            "underestimating": [
                "How quietly a machine credential can persist.",
                "That attacker activity through keys may look like ordinary automation.",
                "The importance of permission scope over the mere existence of the credential.",
            ],
        },
        "customer_guidance": {
            "treating_it_as_devops_noise": {
                "what_it_looks_like": [
                    "They assume new keys are routine in cloud environments.",
                    "They focus on whether the key exists, not how it was used.",
                    "They delay because no user-facing disruption is visible.",
                ],
                "tam_response": [
                    "Reframe the event from deployment noise to persistence risk until proven otherwise.",
                    "Keep focus on permission scope, creation context, and immediate use.",
                    "Guide the team to validate whether the credential aligns with known automation patterns.",
                ],
                "questions_to_ask": [
                    "Was this key expected?",
                    "What did it access after creation?",
                    "Does the creating account normally perform this action?",
                ],
            }
        },
        "platform_value": [
            "Improves visibility into suspicious machine credential creation and use.",
            "Connects key creation to the identity and session that initiated it.",
            "Helps teams avoid missing cloud persistence that does not rely on repeated user login.",
        ],
        "timeline": [
            "Attacker gains or uses an identity with enough access to create credentials.",
            "New API key or token is created outside expected workflow.",
            "Credential is used to access resources programmatically.",
            "If not interrupted, the key provides durable ongoing access.",
        ],
    },
}
