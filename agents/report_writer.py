import json
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage


def safe_json_parse(content: str, fallback: dict) -> dict:
    try:
        content = content.strip()
        if content.startswith("```"):
            content = content.split("```", 2)[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content.strip())
    except Exception:
        return fallback


def generate_report(target: str, plan: dict, recon_data: dict, vuln_data: dict, llm) -> dict:
    print("\n[Report Writer] Generating final report...")

    messages = [
        SystemMessage(content="""You are a penetration testing report writer.

Create a structured penetration testing report using ONLY the provided data.
Do not invent vulnerabilities.

Return ONLY valid JSON in this format:
{
  "agent": "report_writer",
  "status": "success",
  "executive_summary": "summary",
  "findings": [
    {
      "title": "finding",
      "risk": "low/medium/high",
      "evidence": "evidence",
      "recommendation": "fix"
    }
  ],
  "overall_risk": "low",
  "next_steps": ["step1", "step2"]
}
"""),
        HumanMessage(content=json.dumps({
            "target": target,
            "plan": plan,
            "recon": recon_data,
            "vulnerabilities": vuln_data
        }, indent=2))
    ]

    response = llm.invoke(messages)

    fallback = {
        "agent": "report_writer",
        "status": "error",
        "executive_summary": "Failed to generate report",
        "findings": [],
        "overall_risk": "unknown",
        "next_steps": []
    }

    result = safe_json_parse(response.content, fallback)

    print("[Report Writer] Done.")
    return result


if __name__ == "__main__":
    load_dotenv(".enviro_key")
    llm = ChatAnthropic(model="claude-haiku-4-5-20251001")

    test_target = "scanme.nmap.org"
    test_plan = {"plan": ["run nmap", "run whois"], "tools": ["nmap", "whois"], "reasoning": "default test"}
    test_recon = {
        "nmap": {"open_ports": [22, 80], "services": {"22": "ssh", "80": "http"}},
        "whois": {"registrar": "Test Registrar", "country": "US"}
    }
    test_vulns = {
        "findings": [
            {"service": "ssh", "port": 22, "severity": "medium"},
            {"service": "http", "port": 80, "severity": "medium"}
        ]
    }

    report = generate_report(test_target, test_plan, test_recon, test_vulns, llm)
    print(json.dumps(report, indent=2))