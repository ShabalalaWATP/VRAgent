from typing import Any, Dict, List, Optional


class GeminiPlanner:
    """Lightweight Gemini-inspired planner for the scanner sidecar."""

    def __init__(self, model_name: str = "gemini"):
        self.model_name = model_name

    def plan(
        self,
        web_targets: Optional[List[Dict[str, Any]]] = None,
        network_targets: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        web_targets = web_targets or []
        network_targets = network_targets or []
        actions: List[Dict[str, Any]] = []
        phases: List[Dict[str, Any]] = []

        if web_targets:
            phase_actions: List[Dict[str, Any]] = []
            for host in web_targets:
                ip = host.get("ip", host.get("address", ""))
                port = host.get("port", 80)
                target_url = host.get("url") or self._build_url(ip, port)
                service = host.get("service", "http")

                reasoning_nmap = [
                    f"Discovered web service on {ip}:{port} ({service}), so run nmap service scan to fingerprint the stack.",
                    "This establishes a baseline before deeper enumeration."
                ]
                nmap_action = {
                    "phase": "web_discovery",
                    "scan": "nmap",
                    "scan_type": "service",
                    "target": ip or target_url,
                    "reasoning": reasoning_nmap,
                    "params": {
                        "ports": str(port),
                    },
                }
                phase_actions.append(nmap_action)
                actions.append(nmap_action)

                reasoning_dir = [
                    f"With {target_url} confirmed, enumerate directory paths to surface interesting endpoints.",
                    "Gobuster is lightweight and complements the service scan."
                ]
                dir_action = {
                    "phase": "web_enumeration",
                    "scan": "direnum",
                    "target": target_url,
                    "reasoning": reasoning_dir,
                    "params": {
                        "engine": "gobuster",
                        "threads": 25,
                        "timeout": 300,
                    },
                }
                phase_actions.append(dir_action)
                actions.append(dir_action)

            phases.append(
                {
                    "name": "Web Discovery",
                    "description": "Service detection and directory enumeration for HTTP(S) endpoints.",
                    "actions": [self._summarize_action(a) for a in phase_actions],
                }
            )

        if network_targets:
            phase_actions = []
            for host in network_targets:
                ip = host.get("ip", "")
                port = host.get("port", 0)
                service = host.get("service", "network")
                tags = host.get("nuclei_tags", ["cve", "network"])

                reasoning_vuln = [
                    f"{service} on {ip}:{port} suggests network-exposed vulnerabilities, so run a focused nmap vuln scan.",
                    "Follow up with nuclei templates that match the service tags."
                ]
                vuln_action = {
                    "phase": "network_discovery",
                    "scan": "nmap",
                    "scan_type": "vuln",
                    "target": ip,
                    "reasoning": reasoning_vuln,
                    "params": {
                        "ports": str(port),
                    },
                }
                phase_actions.append(vuln_action)
                actions.append(vuln_action)

                reasoning_nuclei = [
                    f"Target {ip}:{port} has tags {tags} so run nuclei templates scoped to those keywords.",
                    "This automates the next vulnerability validation step."
                ]
                nuclei_action = {
                    "phase": "network_enumeration",
                    "scan": "nuclei",
                    "target": f"{ip}:{port}",
                    "reasoning": reasoning_nuclei,
                    "params": {
                        "tags": tags,
                        "severity": ["critical", "high", "medium"],
                        "rate_limit": 200,
                    },
                }
                phase_actions.append(nuclei_action)
                actions.append(nuclei_action)

            phases.append(
                {
                    "name": "Network Discovery",
                    "description": "Nmap vulnerability enumeration followed by nuclei sweep for network services.",
                    "actions": [self._summarize_action(a) for a in phase_actions],
                }
            )

        summary = {
            "agent": self.model_name,
            "total_phases": len(phases),
            "total_actions": len(actions),
        }

        return {"phases": phases, "actions": actions, "summary": summary}

    @staticmethod
    def _build_url(ip: str, port: int) -> str:
        if not ip:
            return ""
        scheme = "https" if port in (443, 8443) else "http"
        return f"{scheme}://{ip}:{port}"

    @staticmethod
    def _summarize_action(action: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "scan": action.get("scan"),
            "phase": action.get("phase"),
            "target": action.get("target"),
            "params": action.get("params"),
            "reasoning_highlights": action.get("reasoning", [])[:2],
        }
