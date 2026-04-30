#vulnerability analysis
import json
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

#target is metasploit
load_dotenv("enviro_key")
llm = ChatAnthropic(model = "claude-haiku-4-5-20251001")

def map_service_to_vul (service: str, port: int, version: str) -> dict:
    service = (service or "").lower()
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
            "reasoning": "SSH is externally exposed and needs review for authenication policy, administrative restrictions, and software patch",
            "recommened_checks": [
                "Verify whether password authentication is enabled",
                "Verify whether root login is disabled",
                "Review SSH version to current security advice",
                "Check for network exposure"
            ]
        })

    elif service in ["http", "https", "apache", "nginx"]:
        finding.update({
            "attack_surface": "web application / web server",
            "vul_classes": [
                "Web application misconfiguration",
                "Outdated web server or software, review needed",
                "TLS and HTTP security header review",
                "Exposed administrative or regular content"
            ],
            "severity": "medium",
            "confidence": "medium",
            "reasoning": "An exposed web service may introduce application-layer and configuration-based risk depending on versions and configuration",
            "recommened_checks": [
                "Review server banners and exposed headers",
                "Check for default pages, portals, and directory listings",
                "Review TLS configuration if HTTPs is present",
                "Review versions against current security advice"
            ]
        })
    elif service in ["ftp", "vsftpd"]:
        finding.update({
            "attack_surface": "file transfer service",
            "vul_classes": [
                "Cleartext credential exposure",
                "Anonymous access or misconfiguration",
                "Legacy service exposure",
                "Outdate service/version review"
            ],
            "severity": "high",
            "confidence": "high",
            "reasoning": "FTP presents elevated risk due to insecure transport and misconfiguration",
            "recommened_checks": [
                "Verify whether anonymous login is disabled",
                "Confirm wheteher encrypted alternatives are needed",
                "Review FTP version to current security advice"
            ]
        })
    elif service == "telenet":
        finding.update({
            "attack_surface": "remote administrative access",
            "vul_classes": [
                "Cleartext remote administration",
                "Legacy insecure protocol exposure",
                "Credential interception risk"
            ],
            "severity": "critical",
            "confidence": "high",
            "reasoning": "Telenet is a legacy plaintext admisitration service and is usually critical risk when exposed",
            "recommened_checks": [
                "Determine whether the service is required",
                "Replace with SSH if applicable",
                "Restrict network exposure as soon as possible"
            ]
        })
    elif service in ["smtp"]:
        finding.update({
            "attack_surface": "mail service",
            "vul_classes": [
                "Open relay and misconfiguration risk",
                "User enumeration exposure",
                "Outdated service/version review needed"
            ],
            "severity": "medium",
            "confidence": "medium",
            "reasoning": "Exposed mail services need to be reviewed for relay restrictions, enumeration behavior, and patch level",
            "recommened_checks": [
                "Check relay restrictions",
                "Review SMTP banner and software version",
                "Assess exposure to user enumeration"
            ]
        })
    elif service in ["domain", "dns"]:
        finding.update({
            "attack_surface": "name resolution infrastructure",
            "vul_classes": [
                "Open recursion risk",
                "Zone transfer misconfiguration",
                "Amplify abuse exposure"
            ],
            "severity": "medium",
            "confidence": "medium",
            "reasoning": "DNS services can expose configuration weaknesses that can affect integrity and abuse resistance",
            "recommened_checks": [
                "Check for open recursion",
                "Check whether zone transfer is restricted",
                "Review external exposure and rate limiting"
            ]
        })
    elif service in ["mysql", "postgresql", "mssql", "mongobd", "redis"]:
        finding.update({
            "attack_surface": "database services",
            "vul_classes": [
                "Direct database exposure",
                "Weak authentication exposure",
                "Misconfiguration risk",
                "Outdate service/version review"
            ],
            "severity": "high",
            "confidence": "high",
            "reasoning": "Directly exposed database services materiall increase attack surface and need close review",
            "recommened_checks": [
                "Verify network access restrictions",
                "Review authentication configuration",
                "Review software version against current advisories"
            ]
        })
    else:
        finding.update({
            "attack_surface": "network-exposed serivce",
            "vul_classes": [
                "General exposed service review",
                "Outdated service/version review",
                "Configuration review needed"
            ],
            "severity": "low",
            "confidence": "low",
            "reasoning": "The service is externally exposed but does not match a specialized mapping rule",
            "recommened_checks": [
                "Validate service necessity",
                "Review software version",
                "Review access restrictions and configuration"
            ]
        })
    return finding

def build_rule_based_findings(recon_data: dict) -> list:
    findings = []
    nmap_result = recon_data.get("nmap", {})

    if nmap_result.get("status") != "success":
        return findings
    
    for entry in nmap_result.get("open_ports", []):
        service = entry.get("service", "unknown")
        port = entry.get("port")
        version = entry.get("version", "unknown")
        findings.append(map_service_to_vul(service, port, version))
    return findings


def summary_with_llm(target: str, recon_data: dict, rule_findings: list) -> dict:
    messages = [
        SystemMessage(content"""
You are a cybersecurity vulnerability analysis assistant.
You analyze reconnaissance results and map them to their respective vulnerability class.

Rules:
- Respond only in valid JSON
- Do not provide explotation steps, payloads, commands, or attack instructions
- Do not claim a host is definitely vulnerable based only on service discovery
- Frame conclusions as hypotheses, risk indicators, or items for verification
- Focus on exposed services, likely attack surfaces, severity, confidence, and recommended defensive checks

Return JSON in this format:
{
    "summary": "short summary",
    "priority_assessment": "short priority statement",
    "top_risks": [
        {
            "service": "name",
            "port": 0,
            "risk": "short description",
            "severity": "low|medium|high|critical",
            "confidence": "low|medium|high"
        }
],
"overall_recommendations": [
        "item 1"
        "item 2"
    ]
}
"""), 
        HumanMessage(content=f"""
Target: {target}

Recon data: 
{json.dumps(recon_data, indent=2)}

Rule-based findings:
{json.dumps(rule_findings, indent=2)}

Generate a concise vulnerability analyst assessment
""")
    ]
    response = llm.invoke(messages)

    try:
        return json.loads(response.content)
    except Exception:
        return {
            "summary": "Unable to parse LLM summary; falling back to rule-based analysis only."
            "priority_assessment": "Review highest severity exposed services first."
            "top_risks": [],
            "overall_recommendations": [
                "Validate externally exposed services",
                "Review service versions and configurations",
                "Minimize unnecessary exposure"
            ]
        }

def run_vul_anal(target: str, recon_data: dict) -> dict:
      try:
            rule_findings = build_rule_based_findings(recon_data)
            llm_summary = summary_with_llm(target, recon_data, rule_findings)

            return {
                  "agent": "vulnerability_analyst",
                  "target": target,
                  "status": "success",
                  "summary": llm_summary.get("summary", "Analysis complete."),
                  "priority_assessment": llm_summary.get("priority_assessment", ""),
                  "findings": rule_findings,
                  "top_risks": llm_summary.get("top_risks", []),
                  "overall_recommendations": llm_summary.get("overall_recommendations", [])
            }
      except Exception as err:
            return {
                  "agent": "vulnerability_analyst",
                  "target": target,
                  "status": "error",
                  "error": str(err)
            }