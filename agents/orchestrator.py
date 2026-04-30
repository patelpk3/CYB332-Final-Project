import json
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from agents.recon import run_recon
from agents.vul_anal import map_service_to_vul
from agents.report_writer import generate_report

load_dotenv(".enviro_key")

llm = ChatAnthropic(model="claude-haiku-4-5-20251001")

#This scope is just for the first push
#IMPORTANT: need to change this when the VM is fully running
SCOPE = ["127.0.0.1", "192.168.1.0/24"]

def is_in_scope(target: str) -> bool:
    return any(target in scope for scope in SCOPE)

def orchestrator(target: str) -> dict:
    print(f"\n Orchestrator has received target: {target}")

    if not is_in_scope(target):
        print(f" The target {target} is out of scope, stopping execute.")
        return {
            "status": "stopped",
            "reason": f"Target {target} is outside the scope",
            "target": target
        }

    print(f" Target is in scope.")

    # Plan recon tasks
    messages = [
        SystemMessage(content="""You are a penetration testing orchestrator.
        Your job is to plan reconnaissance tasks for a given target.
        Always respond in valid JSON format like:
        {
            "plan": ["step1", "step2"],
            "tools": ["nmap", "whois", "hping3"],
            "reasoning": "why these tools"
        }
        """),
        HumanMessage(content=f"Plan a recon task for target: {target}")
    ]

    plan_response = llm.invoke(messages)

    try:
        content = plan_response.content.strip()
        if content.startswith("```"):
            content = content.split("```", 2)[1]
            if content.startswith("json"):
                content = content[4:]
        plan = json.loads(content.strip())
    except Exception:
        plan = {
    "plan": ["run nmap", "run whois", "run hping3 tcp syn probe"],
    "tools": ["nmap", "whois", "hping3"],
    "reasoning": "default fallback"
}

    print(f"Plan: {json.dumps(plan, indent=2)}")

    # Recon agent
    print(f"\nOrchestrator sending out recon agent...")
    recon_findings = run_recon(target)

    # Vulnerability analysis agent
    print(f"\nOrchestrator sending out vulnerability analysis agent...")
    vuln_findings = []
    nmap_data = recon_findings.get("nmap", {})
    for entry in nmap_data.get("open_ports", []):
        result = map_service_to_vul(
            service=entry.get("service", ""),
            port=entry.get("port", 0),
            version=entry.get("version", "unknown")
        )
        vuln_findings.append(result)

    vuln_data = {"status": "success", "findings": vuln_findings}
    print(f"Vulnerability analysis complete. {len(vuln_findings)} finding(s).")

    # Report writer agent
    print(f"\nOrchestrator sending out report writer agent...")
    report = generate_report(target, plan, recon_findings, vuln_data, llm)

    print(f"\nAll agents complete.")
    return report


if __name__ == "__main__":
    results = orchestrator("127.0.0.1")
    print(json.dumps(results, indent=2))
