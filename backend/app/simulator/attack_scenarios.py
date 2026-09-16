import random
import uuid
import datetime
from typing import Dict, Any

class AttackSimulator:
    """
    1-Click MITRE ATT&CK Scenario Generator for SOC Demonstrations, Testing & Verification.
    """
    
    SCENARIOS = {
        "ssh_brute_force": {
            "name": "SSH Brute Force Attack (T1110)",
            "mitre_id": "T1110",
            "mitre_technique": "Brute Force",
            "rule_id": "100001",
            "rule_level": 12,
            "rule_description": "High Risk: Multiple SSH authentication failures from single IP (20+ attempts)",
            "source_ips": ["185.220.101.45", "161.118.212.147", "194.26.29.112"],
            "agent_name": "prod-auth-gateway-01",
            "destination_ip": "10.0.1.50"
        },
        "privilege_escalation": {
            "name": "Privilege Escalation & Rogue Account (T1078 / T1136)",
            "mitre_id": "T1136",
            "mitre_technique": "Create Account & Sudo Group Addition",
            "rule_id": "100002",
            "rule_level": 13,
            "rule_description": "High Risk: Unauthorized user added to system sudoers / wheel group",
            "source_ips": ["87.152.6.217", "45.143.200.12"],
            "agent_name": "prod-db-cluster-02",
            "destination_ip": "10.0.2.14"
        },
        "web_sqli_exploit": {
            "name": "Web Application SQL Injection Exploit (T1190)",
            "mitre_id": "T1190",
            "mitre_technique": "Exploit Public-Facing Application",
            "rule_id": "100003",
            "rule_level": 11,
            "rule_description": "Medium Risk: SQL injection payload detected in HTTP request query parameter",
            "source_ips": ["198.51.100.77", "203.0.113.89"],
            "agent_name": "web-frontend-nginx-01",
            "destination_ip": "10.0.0.80"
        },
        "fim_ransomware": {
            "name": "File Integrity Monitoring - Ransomware Indicator (T1222 / T1486)",
            "mitre_id": "T1486",
            "mitre_technique": "Data Encrypted for Impact",
            "rule_id": "100004",
            "rule_level": 14,
            "rule_description": "CRITICAL: Mass file modification detected in /var/data with high entropy",
            "source_ips": ["185.220.101.45", "195.123.245.8"],
            "agent_name": "storage-nas-backup-01",
            "destination_ip": "10.0.3.22"
        },
        "recon_port_scan": {
            "name": "Network Discovery & Reconnaissance (T1046)",
            "mitre_id": "T1046",
            "mitre_technique": "Network Service Discovery",
            "rule_id": "100005",
            "rule_level": 4,
            "rule_description": "Low Risk: Stealth SYN Port Scan probe against perimeter ports (22, 80, 443, 8080)",
            "source_ips": ["203.0.113.15", "198.51.100.22"],
            "agent_name": "perimeter-dmz-firewall",
            "destination_ip": "10.0.0.1"
        }
    }
    
    @classmethod
    def generate(cls, scenario_key: str = "ssh_brute_force") -> Dict[str, Any]:
        sc = cls.SCENARIOS.get(scenario_key, cls.SCENARIOS["ssh_brute_force"])
        ip = random.choice(sc["source_ips"])
        
        return {
            "id": f"alert-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_ip": ip,
            "destination_ip": sc["destination_ip"],
            "agent_name": sc["agent_name"],
            "rule_id": sc["rule_id"],
            "rule_level": sc["rule_level"],
            "rule_description": sc["rule_description"],
            "mitre_id": sc["mitre_id"],
            "mitre_technique": sc["mitre_technique"],
            "raw_payload": f'{{"event": "{sc["name"]}", "src_ip": "{ip}", "agent": "{sc["agent_name"]}"}}'
        }

attack_simulator = AttackSimulator()
