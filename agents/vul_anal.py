#vulnerability analysis
import json
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

load_dotenv("enviro_key")
llm = ChatAnthropic(model = "claude-haiku-4-5-20251001")

def map_service_to_vul (service: str, port: int, version: str) -> dict:
    service = (service or "").lower
    version = version or "unknown"

    finding = {
        "service": service,
        "port": port,
        "version": version,
        "attack_surface": "unkown",
        "vul_classes": [],
        "severity": "low",
        "confidence": "low",
        "reasoning": "",
        "recommended_checks": []
    }

    if service in ["ssh", "openssh"]:
        finding.update({
            "attack_surface": "remote administrative access",
            "vul_classes": [
                "Weak authentication exposure",
                "Misconfiguration risk",
                "Outdated service/version review needed"
            ],
            "severity": "medium",
            "confidence": "medium",
            "reasoning": "SSH is externally exposed and needs review for authenication policy, administrative restrictions, and software patch"
            "recommened_checks": [
                "Verify whether password authentication is enabled"
                "Verify whether root login is disabled"
                "Review SSH version to current security advice"
                "Check for network exposure"
            ]
        })

    elif service in ["http", "https", "apache", "nginx"]:
                finding.update({
            "attack_surface": "web application / web server",
            "vul_classes": [
                "Web application misconfiguration",
                "Outdated web server or software, review needed",
                "TLS and HTTP security header review"
                "Exposed administrative or regular content"
            ],
            "severity": "medium",
            "confidence": "medium",
            "reasoning": "An exposed web service may introduce application-layer and configuration-based risk depending on versions and configuration"
            "recommened_checks": [
                "Review server banners and exposed headers"
                "Check for default pages, portals, and directory listings"
                "Review TLS configuration if HTTPs is present"
                "Review versions against current security advice"
            ]
        })
    elif service in ["ftp", "vsftpd"]:
           