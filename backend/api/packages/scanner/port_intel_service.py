PORT_DATABASE: dict = {
    "21": {
        "service": "FTP",
        "risk": "critical",
        "desc": "File Transfer Protocol — often transmits credentials in plaintext. Common vector for anonymous access and credential theft.",
        "attacks": [
            "Anonymous FTP login",
            "Brute force credentials",
            "FTP bounce attack",
            "Directory traversal",
        ],
        "recommendation": "Disable FTP entirely. Use SFTP (port 22) or FTPS instead. If required, restrict to specific IPs.",
        "cve_examples": ["CVE-2010-4221"],
        "owasp": "A05:2021",
    },
    "22": {
        "service": "SSH",
        "risk": "medium",
        "desc": "Secure Shell — encrypted remote access. Risk depends on configuration and key management.",
        "attacks": [
            "Brute force (weak passwords)",
            "Key-based auth bypass",
            "SSH tunneling abuse",
        ],
        "recommendation": "Disable password auth, use keys only. Restrict to specific IPs. Use fail2ban. Change default port.",
        "cve_examples": ["CVE-2023-38408"],
        "owasp": "A07:2021",
    },
    "23": {
        "service": "Telnet",
        "risk": "critical",
        "desc": "Telnet transmits ALL data including passwords in plaintext. Should never be exposed on the internet.",
        "attacks": [
            "Credential interception",
            "Session hijacking",
            "Man-in-the-middle",
        ],
        "recommendation": "Disable immediately. Replace with SSH. No exceptions.",
        "cve_examples": [],
        "owasp": "A02:2021",
    },
    "25": {
        "service": "SMTP",
        "risk": "medium",
        "desc": "Mail server. Open relay can allow spam sending. Auth issues can expose email data.",
        "attacks": [
            "Open relay abuse",
            "Email spoofing",
            "VRFY/EXPN enumeration",
        ],
        "recommendation": "Disable open relay. Require authentication. Use TLS. Implement SPF/DKIM/DMARC.",
        "cve_examples": [],
        "owasp": "A05:2021",
    },
    "80": {
        "service": "HTTP",
        "risk": "low",
        "desc": "Unencrypted web traffic. All data transmitted in plaintext. Should redirect to HTTPS.",
        "attacks": [
            "Traffic interception",
            "SSL stripping",
            "Session hijacking",
        ],
        "recommendation": "Redirect all HTTP to HTTPS. Implement HSTS.",
        "cve_examples": [],
        "owasp": "A02:2021",
    },
    "443": {
        "service": "HTTPS",
        "risk": "safe",
        "desc": "Encrypted web traffic. Standard and expected on web servers.",
        "attacks": [],
        "recommendation": "Ensure TLS 1.2+ only. Disable SSLv3, TLS 1.0, TLS 1.1.",
        "cve_examples": [],
        "owasp": None,
    },
    "445": {
        "service": "SMB",
        "risk": "critical",
        "desc": "Windows file sharing. Extremely dangerous when internet-exposed. EternalBlue exploits this port.",
        "attacks": [
            "EternalBlue (MS17-010)",
            "WannaCry ransomware",
            "Credential relay attacks",
            "Pass-the-hash",
        ],
        "recommendation": "Block at firewall immediately. Never expose SMB to the internet.",
        "cve_examples": ["CVE-2017-0144"],
        "owasp": "A06:2021",
    },
    "1433": {
        "service": "MSSQL",
        "risk": "critical",
        "desc": "Microsoft SQL Server. Direct database exposure to internet is extremely dangerous.",
        "attacks": [
            "SQL Server brute force",
            "sa account exploitation",
            "xp_cmdshell OS execution",
        ],
        "recommendation": "Never expose databases to internet. Use VPN or bastion host for access.",
        "cve_examples": [],
        "owasp": "A05:2021",
    },
    "3306": {
        "service": "MySQL",
        "risk": "critical",
        "desc": "MySQL database exposed to internet. Full database access if credentials are weak or default.",
        "attacks": [
            "Root account brute force",
            "Anonymous login",
            "SQL injection via direct connect",
        ],
        "recommendation": "Bind to localhost only (bind-address = 127.0.0.1). Use strong passwords. Never expose to internet.",
        "cve_examples": ["CVE-2012-2122"],
        "owasp": "A05:2021",
    },
    "3389": {
        "service": "RDP",
        "risk": "critical",
        "desc": "Remote Desktop Protocol. Heavily targeted by ransomware groups. BlueKeep exploits this port.",
        "attacks": [
            "BlueKeep (CVE-2019-0708)",
            "DejaBlue",
            "Brute force credentials",
            "Ransomware deployment",
        ],
        "recommendation": "Restrict to VPN only. Enable NLA. Use strong passwords + MFA. Never expose directly to internet.",
        "cve_examples": ["CVE-2019-0708"],
        "owasp": "A06:2021",
    },
    "5432": {
        "service": "PostgreSQL",
        "risk": "critical",
        "desc": "PostgreSQL database exposed to internet. Full data access risk.",
        "attacks": [
            "Brute force postgres account",
            "COPY TO/FROM PROGRAM RCE",
        ],
        "recommendation": "Bind to localhost. Use pg_hba.conf to restrict access. Never expose to internet.",
        "cve_examples": [],
        "owasp": "A05:2021",
    },
    "5900": {
        "service": "VNC",
        "risk": "critical",
        "desc": "VNC remote desktop — often configured with weak or no authentication.",
        "attacks": [
            "No-auth VNC access",
            "Brute force",
            "Screen capture",
        ],
        "recommendation": "Require strong password. Use VPN tunnel. Disable if possible.",
        "cve_examples": [],
        "owasp": "A07:2021",
    },
    "6379": {
        "service": "Redis",
        "risk": "critical",
        "desc": "Redis often has no authentication by default. Full data access + possible RCE via config write.",
        "attacks": [
            "Unauthenticated access",
            "CONFIG SET to write SSH keys",
            "SLAVEOF for data exfiltration",
        ],
        "recommendation": "Bind to 127.0.0.1 only. Enable requirepass. Rename dangerous commands.",
        "cve_examples": ["CVE-2022-0543"],
        "owasp": "A05:2021",
    },
    "8080": {
        "service": "HTTP-Alt",
        "risk": "medium",
        "desc": "Alternate HTTP port — often used for admin panels, dev servers, or proxies.",
        "attacks": [
            "Admin interface exposed",
            "Dev server with debug mode",
        ],
        "recommendation": "Restrict admin interfaces. Use HTTPS. Restrict by IP.",
        "cve_examples": [],
        "owasp": "A05:2021",
    },
    "8443": {
        "service": "HTTPS-Alt",
        "risk": "low",
        "desc": "Alternate HTTPS port — often admin panels or alternative services.",
        "attacks": [],
        "recommendation": "Verify what service is running. Ensure it requires authentication.",
        "cve_examples": [],
        "owasp": None,
    },
    "9200": {
        "service": "Elasticsearch",
        "risk": "critical",
        "desc": "Elasticsearch with no auth by default. Millions of records exposed in past breaches.",
        "attacks": [
            "Unauthenticated data access",
            "Index deletion",
            "Data exfiltration",
        ],
        "recommendation": "Enable X-Pack security. Require authentication. Never expose to internet.",
        "cve_examples": ["CVE-2021-22144"],
        "owasp": "A05:2021",
    },
    "27017": {
        "service": "MongoDB",
        "risk": "critical",
        "desc": "MongoDB with no auth by default. One of the most commonly breached databases.",
        "attacks": [
            "Unauthenticated access",
            "NoSQL injection",
            "Data exfiltration",
        ],
        "recommendation": "Enable authentication. Bind to 127.0.0.1. Use TLS. Never expose to internet.",
        "cve_examples": [],
        "owasp": "A05:2021",
    },
}


def enrich_port(port_data: dict) -> dict:
    port = str(port_data.get("port", ""))
    service = port_data.get("service", "")
    version = port_data.get("version", "")

    intel = PORT_DATABASE.get(
        port,
        {
            "service": service or "Unknown",
            "risk": "low",
            "desc": f"Port {port} ({service}) is open. Verify if this service should be publicly accessible.",
            "attacks": [],
            "recommendation": "Verify if this port needs to be publicly accessible. Restrict if not required.",
            "cve_examples": [],
            "owasp": None,
        },
    )

    cve_hints = []
    if version:
        v_lower = version.lower()
        if "apache/2.4.4" in v_lower or "apache/2.4.49" in v_lower:
            cve_hints.append("CVE-2021-41773 (Path traversal)")
        if "nginx/1.1" in v_lower:
            cve_hints.append("CVE-2013-2028 (Stack overflow)")
        if "openssh_7" in v_lower:
            cve_hints.append("CVE-2016-6210 (User enumeration)")

    return {
        **port_data,
        "intel": intel,
        "cve_hints": cve_hints,
        "display_risk": intel.get("risk", "low"),
    }


def analyze_port_exposure(open_ports: list) -> dict:
    critical = [
        p
        for p in open_ports
        if PORT_DATABASE.get(str(p.get("port", "")), {}).get("risk") == "critical"
    ]
    dangerous_combos = []

    ports_open = {str(p.get("port", "")) for p in open_ports}

    if "3306" in ports_open and "80" in ports_open:
        dangerous_combos.append(
            {
                "combo": "MySQL + HTTP",
                "risk": "Database and web server on same host — SQL injection could give direct DB access",
                "severity": "critical",
            }
        )

    if "6379" in ports_open:
        dangerous_combos.append(
            {
                "combo": "Redis exposed",
                "risk": "Unauthenticated Redis can be used to write SSH keys and gain root access",
                "severity": "critical",
            }
        )

    if "445" in ports_open:
        dangerous_combos.append(
            {
                "combo": "SMB exposed",
                "risk": "EternalBlue exploit possible — same attack used by WannaCry ransomware",
                "severity": "critical",
            }
        )

    return {
        "critical_ports": critical,
        "dangerous_combos": dangerous_combos,
        "total_exposed": len(open_ports),
        "total_critical": len(critical),
    }
