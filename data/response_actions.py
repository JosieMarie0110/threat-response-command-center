SOC_MONITORING = {
    "initial_access": [
        "Suspicious sign-in attempts followed by successful authentication from unusual geolocation, impossible travel patterns, or unmanaged devices.",
        "Repeated failed logins, password spray patterns, MFA fatigue prompts, or unusual authentication sequences tied to a single user or source.",
        "New browser sessions, proxy activity, or endpoint telemetry appearing immediately after suspicious identity events.",
        "Public-facing access points such as VPN, RDP, Citrix, SSH, or web apps showing brute-force attempts followed by successful access.",
        "Identity activity that looks technically valid but behaviorally abnormal, such as new device use, unusual time of access, or unusual resource targeting."
    ],

    "execution": [
        "Process trees showing suspicious parent-child behavior such as Office spawning PowerShell, cmd, rundll32, mshta, or similar tools.",
        "Command-line arguments indicating encoded commands, download cradles, script execution, or living-off-the-land behavior.",
        "Malicious or suspicious file execution followed by child processes, scheduled tasks, registry changes, or outbound network traffic.",
        "Endpoint events showing script engine abuse, macro-driven execution, or suspicious use of native Windows binaries.",
        "Execution behavior that is quickly followed by network callback, privilege use, or repeated execution across more than one host."
    ],

    "persistence": [
        "Creation or modification of scheduled tasks, services, autoruns, registry run keys, startup folders, login scripts, or shell behavior.",
        "Repeated execution activity returning after reboot, logout, or apparent cleanup on the same system.",
        "Mailbox rules, OAuth grants, application consents, new trust relationships, or suspicious SaaS admin changes that could provide re-entry.",
        "Persistence artifacts appearing shortly after execution or initial access events, especially when tied to the same user or host.",
        "The same persistence mechanism or artifact appearing across multiple endpoints, identities, or cloud resources."
    ],

    "privilege_escalation": [
        "Authentication or admin activity indicating a user suddenly obtained higher privilege than expected for their normal role.",
        "Service account use, delegated trust, or remote tooling behavior that appears immediately after lower-level compromise.",
        "Role changes, token abuse, privilege assignment, or misuse of built-in administrative tools across endpoint and identity telemetry.",
        "Evidence that a newly elevated identity is now touching sensitive systems, admin pathways, or configuration controls.",
        "Privilege increases that occur close in time to suspicious host behavior, credential access, or lateral movement attempts."
    ],

    "defense_evasion": [
        "Security agent tampering, service stoppage, policy changes, exclusions, or suspicious disablement of protections on the host.",
        "Encoded commands, renamed tools, obfuscated scripts, or use of LOLBins in contexts that attempt to hide intent.",
        "Gaps in expected endpoint or logging telemetry that align with suspicious activity windows.",
        "Log clearing, timestomping, artifact deletion, or control-plane changes that reduce investigation visibility.",
        "Behavior suggesting the attacker is deliberately weakening visibility before movement, exfiltration, or impact."
    ],

    "credential_access": [
        "Processes attempting to access LSASS, memory, browser stores, token material, or other sensitive trust locations.",
        "Suspicious collection of cookies, browser credentials, cached sessions, vault entries, or application secrets.",
        "Authentication reuse after host compromise, especially when the same account appears on new systems unexpectedly.",
        "Access to secret stores, password managers, configuration files, or service accounts shortly after execution or privilege escalation.",
        "Credential theft indicators followed by new logins, remote access, or movement behavior tied to the same identity."
    ],

    "discovery": [
        "Enumeration of users, groups, hosts, domains, trusts, shares, and internal services using command-line tools or scripts.",
        "Internal scans, service checks, network probing, or repeated connection attempts that suggest mapping activity.",
        "Reconnaissance against EDR, AV, logging tools, backup systems, identity platforms, or sensitive data stores.",
        "Slow or low-noise discovery patterns that look operational on the surface but expand steadily across the environment.",
        "Discovery behavior focused on administrative pathways, crown-jewel assets, backups, or high-value business systems."
    ],

    "lateral_movement": [
        "Remote access behavior using RDP, SMB, WinRM, SSH, PsExec, remote services, or admin tooling across multiple systems.",
        "Authentication events showing the same account or credential set being reused across internal hosts in a short time window.",
        "Endpoint evidence of remote execution paired with east-west traffic or service creation on destination hosts.",
        "Cloud or SaaS pivots such as role assumption, delegated access, mailbox movement, or cross-platform trust expansion.",
        "Movement patterns that indicate spread toward servers, privileged systems, or high-value business applications."
    ],

    "collection": [
        "Bulk file access, share traversal, mailbox access, or repeated reads against sensitive directories, repositories, or business data stores.",
        "Archive creation, compression activity, staging folders, or unusual local file packaging before outbound transfer.",
        "Collection focused on HR, finance, legal, engineering, executive, customer, or regulated data locations.",
        "Large-scale or targeted mailbox and communication platform access that suggests theft of approvals, trust, or sensitive content.",
        "Collection behavior that is immediately followed by staging, outbound traffic, or repeated access attempts against the same data sources."
    ],

    "command_and_control": [
        "Periodic outbound traffic or beaconing patterns to suspicious domains, IPs, or cloud-based destinations.",
        "Remote management or support tooling used outside normal support windows, accounts, or device baselines.",
        "DNS, HTTPS, or trusted cloud channels carrying repeated low-volume communication patterns consistent with callback behavior.",
        "Suspicious processes on the endpoint that align with outbound communication timing and remote tasking behavior.",
        "Multiple systems showing similar callback infrastructure, timing patterns, or remote control indicators."
    ],

    "exfiltration": [
        "Outbound data transfer spikes to external destinations, especially after internal staging, archive creation, or sensitive data access.",
        "Uploads over trusted cloud services, encrypted channels, or otherwise allowed traffic that do not fit normal business patterns.",
        "Slow or fragmented transfers that individually look small but together suggest deliberate external movement of data.",
        "Transfer activity tied to the same identity, host, or archive that was previously involved in collection or staging.",
        "Evidence that data moved from access to staging to external transfer, even if transfer confirmation is still being validated."
    ],

    "impact": [
        "Mass encryption, widespread file modifications, ransom note creation, file access failures, or sudden service disruption.",
        "Identity instability, backup access anomalies, or disruption to critical recovery dependencies during the incident window.",
        "Application outages, workflow interruption, admin lockouts, or service degradation that directly affect business operations.",
        "Rapid spread of disruptive behavior across multiple systems, shares, or business functions.",
        "Signs that the environment is moving from investigation into active continuity and recovery decision-making."
    ]
}
