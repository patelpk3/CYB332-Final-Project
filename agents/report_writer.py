import json
from langchain_core.messages import HumanMessage, SystemMessage


def safe_json_parse(content: str, fallback: dict) -> dict:
    try:
        return json.loads(content)
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