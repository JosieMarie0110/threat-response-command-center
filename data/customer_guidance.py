ANALYST_VALIDATION = {
    "initial_access": [
        {
            "question": "Did access actually succeed, or are we only seeing targeting activity?",
            "answer": "Validate whether the suspicious event resulted in a live authenticated session, successful remote access, or follow-on activity on a host, browser, or application. The goal is to separate attempted compromise from confirmed foothold."
        },
        {
            "question": "What evidence would confirm this moved beyond a single suspicious login?",
            "answer": "Check for session continuity, new device registration, proxy activity, mailbox activity, SaaS access, or endpoint telemetry tied closely to the identity event. If multiple control planes support the same story, confidence rises quickly."
        },
        {
            "question": "Is this one user issue, or the start of a broader identity pattern?",
            "answer": "Look for related failures, password spray behavior, repeated MFA prompts, nearby suspicious logins, or shared infrastructure touching multiple accounts. The analyst is determining whether this is isolated compromise or campaign behavior."
        },
        {
            "question": "What makes this access abnormal even if the login appears valid?",
            "answer": "Validate behavioral anomalies such as unusual device, geolocation, timing, impossible travel, unusual resource access, or login sequence changes. The key is proving why technically valid activity may still be attacker-controlled."
        }
    ],

    "execution": [
        {
            "question": "Did malicious code actually execute, or was suspicious content only delivered?",
            "answer": "Confirm whether the file, script, or command launched and produced a real process chain. Delivery alone is not enough. The analyst needs evidence of execution on the host."
        },
        {
            "question": "What process lineage proves this was harmful rather than normal administration?",
            "answer": "Validate parent-child process relationships, suspicious command-line arguments, script engine behavior, LOLBin usage, downloaded payloads, or execution from unusual paths. The goal is to distinguish malicious behavior from legitimate admin activity."
        },
        {
            "question": "What happened immediately after execution?",
            "answer": "Determine whether execution led to callback traffic, persistence artifacts, credential access, privilege use, or activity on another host. This defines whether execution was contained or became the start of broader compromise."
        },
        {
            "question": "How confident are we that this is attacker-driven activity?",
            "answer": "Increase confidence by correlating endpoint behavior with network activity, reputation context, identity signals, and repeated malicious patterns. The analyst is trying to move from suspicious artifact to confirmed malicious action."
        }
    ],

    "persistence": [
        {
            "question": "What exact mechanism would let the attacker come back?",
            "answer": "Validate the specific re-entry path such as scheduled task, service, autorun, registry change, startup item, mailbox rule, OAuth grant, new account, or SaaS trust change. The goal is to identify the mechanism, not just the symptom."
        },
        {
            "question": "Does the persistence exist only on the host, or also in identity, SaaS, or cloud control planes?",
            "answer": "Check whether the attacker planted persistence outside the endpoint through app consents, delegated roles, inbox rules, federation abuse, or cloud identity changes. Recovery is weak if only the host is cleaned."
        },
        {
            "question": "Is the persistence method isolated or repeated elsewhere?",
            "answer": "Hunt for the same technique, artifact, task name, binary path, registry key, script, or trust change across other systems and identities. Analysts need to know whether cleanup must stay local or become environment-wide."
        },
        {
            "question": "What would prove cleanup is real rather than temporary?",
            "answer": "The analyst needs evidence that the re-entry path is removed, related accounts and trust are reset, and the behavior does not return after reboot, reauthentication, or monitoring follow-up."
        }
    ],

    "privilege_escalation": [
        {
            "question": "What privilege changed, exactly?",
            "answer": "Validate whether the attacker gained local admin, domain-level privilege, elevated cloud role, delegated SaaS access, service account reach, or administrative token use. The specific trust gained determines severity."
        },
        {
            "question": "How was higher privilege obtained?",
            "answer": "Determine whether elevation came from stolen credentials, token abuse, misconfiguration, vulnerable service, delegated trust, or inherited administrative pathway. This identifies both attacker method and control weakness."
        },
        {
            "question": "What did the attacker do immediately after gaining privilege?",
            "answer": "Check for account changes, security tool tampering, credential dumping, remote access, policy modification, or spread to new systems. Post-escalation behavior often defines the true blast radius."
        },
        {
            "question": "Did the new privilege cross into other platforms or trust zones?",
            "answer": "Validate whether the elevated access touched servers, identity platforms, cloud management, backup systems, SaaS admin consoles, or other high-value control planes. This shows whether the incident stayed local or became enterprise risk."
        }
    ],

    "defense_evasion": [
        {
            "question": "Which controls were weakened, disabled, or bypassed?",
            "answer": "Validate whether endpoint agents, policies, logging, detections, anti-malware controls, or administration boundaries were modified. The analyst needs to know exactly what visibility or protection was lost."
        },
        {
            "question": "What evidence is now missing because of the evasion?",
            "answer": "Determine whether telemetry gaps, missing logs, altered timestamps, deleted artifacts, or reduced endpoint visibility now exist. This shapes how much confidence is possible and where alternate evidence is needed."
        },
        {
            "question": "What did the attacker seem to be preparing for by evading controls?",
            "answer": "Look at what followed or was about to follow: movement, credential theft, exfiltration, or encryption. Evasion often exists to create space for the next step."
        },
        {
            "question": "Was the evasion opportunistic, built into tooling, or operator-driven?",
            "answer": "Understanding whether the behavior was automated, malware-native, or hands-on-keyboard helps the analyst judge sophistication, intent, and likely follow-on actions."
        }
    ],

    "credential_access": [
        {
            "question": "What trust material was actually exposed or stolen?",
            "answer": "Validate whether this involved passwords, hashes, tokens, cookies, browser credentials, vault contents, API keys, service secrets, or session material. The type of trust stolen determines the containment priority."
        },
        {
            "question": "Is there evidence the stolen trust has already been reused?",
            "answer": "Check for new logins, session continuity, access from additional systems, remote administration, or unusual SaaS behavior shortly after the credential theft indicator. Reuse changes urgency immediately."
        },
        {
            "question": "Which accounts or secrets create the highest downstream risk?",
            "answer": "Prioritize administrative, shared, service, cloud, and high-business-impact accounts first. The analyst is identifying which trust paths could expand the incident fastest."
        },
        {
            "question": "What must be reset, revoked, or invalidated to break the attacker’s access?",
            "answer": "The goal is not just password reset. Analysts must determine whether tokens, cookies, app grants, secrets, or delegated trust also need to be revoked to truly restore confidence."
        }
    ],

    "discovery": [
        {
            "question": "What was the attacker trying to learn?",
            "answer": "Validate whether the reconnaissance focused on users, groups, hosts, shares, administrative pathways, security tools, backups, or sensitive data locations. The discovery target helps predict intent."
        },
        {
            "question": "Was the activity broad reconnaissance or focused preparation?",
            "answer": "Broad enumeration suggests environmental mapping, while targeted discovery against admins, crown-jewel systems, backups, or business-critical apps suggests a more directed next move."
        },
        {
            "question": "What likely next phase does this discovery support?",
            "answer": "Discovery often points toward privilege escalation, lateral movement, evasion, collection, or impact. The analyst should use this phase to get ahead of likely progression."
        },
        {
            "question": "Which assets should be protected now based on what the attacker was studying?",
            "answer": "The best answer here identifies likely next targets such as privileged groups, servers, identity infrastructure, backups, or regulated data stores so defense can shift before damage occurs."
        }
    ],

    "lateral_movement": [
        {
            "question": "Where did the movement begin, and where did it land?",
            "answer": "Validate the source system, destination system, timing, identity, and remote access method. The analyst is building the spread path, not just confirming another alert."
        },
        {
            "question": "What trust path enabled the spread?",
            "answer": "Determine whether the movement relied on reused credentials, admin shares, RDP, SMB, WinRM, SSH, remote tooling, service accounts, cloud role assumption, or delegated SaaS trust."
        },
        {
            "question": "How far has the spread gone so far?",
            "answer": "Check whether movement is limited to a few adjacent systems or already touching servers, privileged environments, or business-critical applications. This defines whether containment stays tactical or becomes wider incident response."
        },
        {
            "question": "What destination systems matter most if they were reached?",
            "answer": "The analyst should identify crown-jewel assets, domain controllers, identity platforms, backups, production systems, or sensitive business apps. Spread matters most when it reaches control or continuity dependencies."
        }
    ],

    "collection": [
        {
            "question": "What data or content was the attacker trying to gather?",
            "answer": "Validate whether the focus was on file shares, HR, finance, legal, engineering, customer data, communications, source code, or regulated information. The content type shapes exposure and response."
        },
        {
            "question": "Was the data only accessed, or was it also staged for transfer?",
            "answer": "Look for archive creation, compression, staging folders, repeated reads, or unusual packaging behavior. Collection becomes more serious when it starts preparing for movement."
        },
        {
            "question": "How sensitive or regulated is the targeted content?",
            "answer": "Analysts should identify whether the content carries legal, privacy, contractual, executive, or operational sensitivity. This is the bridge from technical signal to business consequence."
        },
        {
            "question": "Does the pattern suggest theft, extortion preparation, or both?",
            "answer": "Targeted collection plus staging, mailbox access, archive creation, or simultaneous disruptive behavior may indicate preparation for exfiltration, extortion, or public pressure tactics."
        }
    ],

    "command_and_control": [
        {
            "question": "Is the attacker communication channel still active?",
            "answer": "Validate whether the callback is ongoing, periodic, interactive, or already severed. Active control changes the urgency of containment immediately."
        },
        {
            "question": "How many systems appear tied to the same channel or infrastructure?",
            "answer": "Check for shared destinations, beacon timing, common processes, repeated user-agent patterns, or linked remote tooling. One callback may actually represent a multi-host incident."
        },
        {
            "question": "What kind of control does the channel appear to provide?",
            "answer": "Determine whether the communication supports simple beaconing, file transfer, remote tasking, hands-on-keyboard interaction, or deployment of additional payloads. This helps define attacker maturity and risk."
        },
        {
            "question": "What attacker behavior aligns with the callback timing?",
            "answer": "Correlate the channel with process launches, execution, credential access, remote commands, or spread. The analyst is proving that the network signal represents active attacker coordination."
        }
    ],

    "exfiltration": [
        {
            "question": "Was data only staged internally, or was it actually transferred out?",
            "answer": "The analyst needs to distinguish clearly between access, staging, attempted transfer, and confirmed transfer. Those are not the same thing, and each carries different response implications."
        },
        {
            "question": "What destination, service, or channel was used for transfer?",
            "answer": "Validate whether the data moved to attacker infrastructure, cloud storage, trusted SaaS, encrypted web traffic, or fragmented outbound sessions. The egress path affects containment and breach assessment."
        },
        {
            "question": "What kind of information appears to have left the environment?",
            "answer": "The answer should identify data class, likely sensitivity, and whether the content is customer, employee, executive, legal, financial, or regulated in nature."
        },
        {
            "question": "What obligations or stakeholder actions might confirmation trigger?",
            "answer": "Analysts should surface whether legal, privacy, compliance, contracts, regulators, leadership, or customer communications may now need to be involved."
        }
    ],

    "impact": [
        {
            "question": "Is the disruptive activity still spreading right now?",
            "answer": "Validate whether encryption, deletion, service interruption, or business process failure is ongoing across additional systems, users, or functions. This determines whether the incident is still actively worsening."
        },
        {
            "question": "What business capability is currently down, degraded, or at immediate risk?",
            "answer": "The analyst should define the operational consequence in plain terms: identity access, application availability, file access, manufacturing, payments, communications, or another core function."
        },
        {
            "question": "Are backups, identity, and recovery dependencies still trustworthy?",
            "answer": "Recovery confidence depends on whether the attacker also touched backup systems, admin accounts, identity platforms, or continuity infrastructure."
        },
        {
            "question": "What must be true before recovery is considered safe rather than just fast?",
            "answer": "The analyst needs evidence that active attacker control is removed, re-entry paths are closed, core dependencies are trustworthy, and restoration will not recreate the same compromise."
        }
    ]
}
