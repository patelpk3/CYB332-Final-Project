import json
import logging
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from agents.recon import run_recon
from agents.vul_anal import run_vul_anal
from agents.report_writer import generate_report

load_dotenv(".enviro_key")

# Logging setup — creates pentest_log.txt automatically
logging.basicConfig(
    filename="LLM_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

llm = ChatAnthropic(model="claude-haiku-4-5-20251001")

# Gaurdrail trade off, this can be updated before running
SCOPE = ["127.0.0.1", "scanme.org", "testphp.vulnweb.com", "172.17.0.2", "10.0.2.15"]
#scope checking/blocking 
def is_in_scope(target: str) -> bool:
    blocked = ["0.0.0.0", "255.255.255.255", ""]
    if target.strip() in blocked:
        return False
    return target.strip() in SCOPE
#Orchestrator communication
def orchestrator(target: str) -> dict:
    print(f"\n Orchestrator has received target: {target}")
    logging.info(f"Target received: {target}")

    if not is_in_scope(target):
        print(f" The target {target} is out of scope, stopping execute.")
        logging.warning(f"Target {target} is out of scope. Halting.")
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
    logging.info(f"LLM plan response: {plan_response.content}")

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
    logging.info(f"Plan generated: {json.dumps(plan)}")

    # Recon agent
    print(f"\nOrchestrator sending out recon agent...")
    recon_findings = run_recon(target)
    logging.info(f"Recon findings: {json.dumps(recon_findings)}")

    # Vulnerability analysis agent
    vuln_data = run_vul_anal(target, recon_findings)
    logging.info(f"Vuln findings: {json.dumps(vuln_data)}")
    print(f"Vulnerability analysis complete. {len(vuln_data.get('findings', []))} finding(s).")

    # Report writer agent
    print(f"\nOrchestrator sending out report writer agent...")
    report = generate_report(target, plan, recon_findings, vuln_data, llm)
    logging.info(f"Report generated: {json.dumps(report)}")

    print(f"\nAll agents complete.")
    return report


if __name__ == "__main__":
    results = orchestrator("127.0.0.1")
    print(json.dumps(results, indent=2))