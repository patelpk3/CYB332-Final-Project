import json
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from agents.recon import run_recon
load_dotenv(".enviro_key")

# Set the LLM we are using, haiku
llm = ChatAnthropic(model="claude-haiku-4-5-20251001")

#This scope is just for the first push
#IMPORTANT: need to change this when the VM is fully running
SCOPE = ["scanme.nmap.org", "192.168.1.0/24"]

#Verify the scope
def is_in_scope(target: str) -> bool:
    return any(target in scope for scope in SCOPE)

def orchestrator(target: str) -> dict:
    print(f"\n Orchestrator has received target: {target}")

    # SCOPE error handle
    if not is_in_scope(target):
        print(f" The target {target} is out of scope, stopping execute.")
        return {
            "status": "stopped",
            "reason": f"Target {target} is outside the scope",
            "target": target
        }

    #Confirm target is valid to user
    print(f" Target is in scope.")

    # Ask our LLM to plan the recon task sequence
    messages = [
        SystemMessage(content="""You are a penetration testing orchestrator.
        Your job is to plan reconnaissance tasks for a given target.
        Always respond in valid JSON format like:
        {
            "plan": ["step1", "step2"],
            "tools": ["nmap", "whois"],
            "reasoning": "why these tools"
        }
        """),
        HumanMessage(content=f"Plan a recon task for target: {target}")
    ]

    plan_response = llm.invoke(messages)

    try:
        plan = json.loads(plan_response.content)
    except Exception:
        plan = {"plan": ["run nmap", "run whois"], "tools": ["nmap", "whois"], "reasoning": "default fallback"}

    print(f"Plan: {json.dumps(plan, indent=2)}")

    # Dispatch recon agent
    print(f"\nOrchastator sending out recon agent...")
    recon_findings = run_recon(target)

    # Paste the findings from all agents
    findings = {
        "status": "success",
        "target": target,
        "plan": plan,
        "recon": recon_findings
    }

    print(f"\nAll agents complete. Findings are being printed.")
    return findings


if __name__ == "__main__":
    results = orchestrator("scanme.nmap.org")
print(json.dumps(results, indent=2))
