from dotenv import load_dotenv

# local files
from agents.orchestrator import orchestrator
from agents.recon import run_recon
from agents.vul_anal import print_vul_info 

load_dotenv()

def mock_llm(state: MessagesState):
    return {"messages": [{"role": "ai", "content": "hello world"}]}

def menu():
    print("Welcome")
    options = {
        "orchestrator": orchestrator("google.com"),
        "recon": run_recon,
        "vul_anal": print_vul_info,
        "report_writer": generate_report
    }

    for i, opt in enumerate(options, 1):
        print(f"{i}. {opt}")

    choice = int(input("Select: ")) - 1
menu()
