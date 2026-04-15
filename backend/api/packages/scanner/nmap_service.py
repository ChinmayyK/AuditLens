import subprocess
import xml.etree.ElementTree as ET
import os
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

DANGEROUS_PORTS = {
    "21":    ("FTP Exposed",           "high",
               "FTP transmits credentials in plaintext. "
               "Attacker intercepts login credentials."),
    "23":    ("Telnet Exposed",        "critical",
               "Telnet is completely unencrypted. Every "
               "keystroke visible to network attackers."),
    "25":    ("SMTP Open",             "medium",
               "Mail server exposed. May allow spam "
               "relay or user enumeration."),
    "3306":  ("MySQL DB Exposed",      "critical",
               "Database port directly reachable. "
               "Brute-force or exploit attempts likely."),
    "5432":  ("PostgreSQL Exposed",    "critical",
               "PostgreSQL reachable from internet. "
               "Direct database attack surface."),
    "27017": ("MongoDB Exposed",       "critical",
               "MongoDB often runs with no auth. "
               "Direct data access possible."),
    "6379":  ("Redis Exposed",         "critical",
               "Redis has no auth by default. Full "
               "server compromise via config write."),
    "9200":  ("Elasticsearch Exposed", "critical",
               "Elasticsearch often has no auth. "
               "All indexed data readable."),
    "8080":  ("Alt HTTP Port Open",    "medium",
               "Secondary HTTP port may bypass WAF "
               "or firewall rules."),
    "8443":  ("Alt HTTPS Port Open",   "medium",
               "Secondary HTTPS port may expose "
               "development or admin endpoints."),
    "445":   ("SMB Exposed",           "critical",
               "Windows file sharing exposed. "
               "EternalBlue and similar exploits apply."),
    "3389":  ("RDP Exposed",           "critical",
               "Remote desktop directly exposed. "
               "Brute force and BlueKeep risk."),
    "5900":  ("VNC Exposed",           "high",
               "VNC remote desktop exposed. Often "
               "weak or no authentication."),
    "2049":  ("NFS Exposed",           "high",
               "Network file system exposed. May "
               "allow unauthenticated file access."),
    "11211": ("Memcached Exposed",     "high",
               "Memcached has no auth. Data leak "
               "and amplification DDoS possible."),
}


class NmapService:

    def scan(self, target_url: str,
             scan_id: str) -> dict:
        domain = urlparse(target_url).netloc.split(":")[0]
        output_file = f"/tmp/{scan_id}_nmap.xml"

        cmd = [
            "nmap",
            "-sV",            # service version
            "-sC",            # default scripts
            "--top-ports", "1000",
            "-T4",            # aggressive timing
            "-oX", output_file,
            "--host-timeout", "120s",
            "--open",         # only show open ports
            domain,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=150,
            )
            if result.returncode not in [0, 1]:
                logger.warning(
                    f"Nmap returned {result.returncode}: "
                    f"{result.stderr[:200]}"
                )
        except subprocess.TimeoutExpired:
            logger.warning("Nmap timed out")
            return {"open_ports": [], "findings": [],
                    "os_guess": "Unknown"}
        except FileNotFoundError:
            logger.warning("Nmap not installed")
            return {"open_ports": [], "findings": [],
                    "os_guess": "Unknown"}

        return self._parse_xml(output_file, scan_id)

    def _parse_xml(self, xml_file: str,
                   scan_id: str) -> dict:
        result = {
            "open_ports": [],
            "os_guess":   "Unknown",
            "findings":   [],
        }

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except Exception as e:
            logger.error(f"Nmap XML parse error: {e}")
            return result

        for host in root.findall("host"):
            # OS detection
            for osmatch in host.findall(".//osmatch"):
                result["os_guess"] = \
                    osmatch.get("name", "Unknown")
                break

            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or \
                   state.get("state") != "open":
                    continue

                portid = port.get("portid", "")
                svc = port.find("service")
                svc_name = svc.get("name", "unknown") \
                              if svc is not None else "unknown"
                svc_product = svc.get("product", "") \
                              if svc is not None else ""
                svc_version = svc.get("version", "") \
                              if svc is not None else ""
                version_str = \
                    f"{svc_product} {svc_version}".strip()

                port_info = {
                    "port":    portid,
                    "service": svc_name,
                    "version": version_str,
                    "state":   "open",
                }
                result["open_ports"].append(port_info)

                if portid in DANGEROUS_PORTS:
                    name, sev, desc = \
                        DANGEROUS_PORTS[portid]
                    result["findings"].append({
                        "scan_id":      scan_id,
                        "vuln_type":    name,
                        "severity":     sev,
                        "category":     "network",
                        "url":
                            f"{portid}/{svc_name}",
                        "evidence":
                            f"Port {portid} open — "
                            f"{version_str or svc_name}",
                        "description":  desc,
                        "attack_worked": True,
                        "was_attempted": True,
                        "tool_source":   "nmap",
                        "owasp_category":
                            "A05:2021 - Security "
                            "Misconfiguration",
                        "money_loss_min": 50000,
                        "money_loss_max": 5000000,
                        "attack_name":
                            f"Direct {svc_name.upper()} "
                            f"Port Exploitation",
                    })

        return result
