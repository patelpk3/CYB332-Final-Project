import json
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
load_dotenv(".enviro_key")

def safe_json_parse(content: str, fallback: dict) -> dict:
    # Strip markdown code fences (```json ... ```) that the LLM sometimes wraps around JSON
    try:
        content = content.strip()
        if content.startswith("```"):
            # Split on ``` and take the middle block (the actual content)
            content = content.split("```", 2)[1]
            if content.startswith("json"):
                # Remove the "json" language tag that follows the opening fence
                content = content[4:]
        return json.loads(content.strip())
    except Exception:
        # Return the fallback structure if parsing fails so the pipeline never crashes
        return fallback


def generate_report(target: str, plan: dict, recon_data: dict, vuln_data: dict, llm) -> dict:
    # Combines recon and vulnerability data into a structured penetration test report via the LLM
    print("\n[Report Writer] Generating final report...")

    # System prompt instructs the LLM to act as a report writer and enforces strict JSON output
    # The format mirrors a real penetration test report: summary, findings, risk, and next steps
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
        # Human message bundles all pipeline data so the LLM has full context in one call
        HumanMessage(content=json.dumps({
            "target": target,
            "plan": plan,
            "recon": recon_data,
            "vulnerabilities": vuln_data
        }, indent=2))
    ]

    response = llm.invoke(messages)

    # Fallback returned if the LLM response cannot be parsed as valid JSON
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
    # Load API keys from the project-specific env file
    llm = ChatAnthropic(model="claude-haiku-4-5-20251001")

    # Sample data to test the report writer in isolation without running the full pipeline
    test_target = "127.0.0.1"
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
