from langgraph.graph import StateGraph, MessagesState, START, END
from dotenv import load_dotenv

# local files
from agents.orchestrator import orchestrator
from agents.recon import run_recon

load_dotenv()

def mock_llm(state: MessagesState):
    return {"messages": [{"role": "ai", "content": "hello world"}]}

graph = StateGraph(MessagesState)
graph.add_node(mock_llm)
graph.add_edge(START, "mock_llm")
graph.add_edge("mock_llm", END)
graph = graph.compile()

graph.invoke({"messages": [{"role": "user", "content": "hi!"}]})


def menu():
    options = {
        "orchestrator": orchestrator("google.com"),
        "recon": run_recon,
    }

    for i, opt in enumerate(options, 1):
        print(f"{i}. {opt}")

    choice = int(input("Select: ")) - 1
menu()
