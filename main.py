import json
from dotenv import load_dotenv

# local files
from agents.orchestrator import orchestrator, is_in_scope
from agents.recon import run_recon
load_dotenv(".enviro_key")

def print_result(result):
    """Pretty prints the result and saves to file."""
    print("\n" + "="*55)
    print("        PENETRATION TEST REPORT")
    print("="*55)
    
    if isinstance(result, dict) and "executive_summary" in result:
        print(f"\nEXECUTIVE SUMMARY:")
        print(f"{result['executive_summary']}")
        
        print(f"\nOVERALL RISK: {result.get('overall_risk', 'N/A').upper()}")
        
        print(f"\nFINDINGS ({len(result.get('findings', []))}):")
        for i, finding in enumerate(result.get('findings', []), 1):
            print(f"\n  [{i}] {finding.get('title', 'N/A')}")
            print(f"      Risk:       {finding.get('risk', 'N/A').upper()}")
            print(f"      Evidence:   {finding.get('evidence', 'N/A')}")
            print(f"      Fix:        {finding.get('recommendation', 'N/A')}")
        
        print(f"\nNEXT STEPS:")
        for i, step in enumerate(result.get('next_steps', []), 1):
            print(f"  {i}. {step}")
        
        # Save full report to file
        with open("report_output.json", "w") as f:
            json.dump(result, f, indent=2)
        print("\n" + "="*55)
        print("Full report saved to report_output.json")
        print("="*55)
    else:
        print(json.dumps(result, indent=2))

def menu():
    print("\n=== Penetration Testing Menu ===")
    options = {
        1: ("Full Orchestration", "orchestrator"),
        2: ("Reconnaissance Only", "recon"),
        3: ("Check If Target In Scope", "scope_check")
    }

    for num, (name, _) in options.items():
        print(f"{num}. {name}")
    print("0. Exit")

    try:
        choice = int(input("\nSelect an option: "))
        
        if choice == 0:
            print("Exiting...")
            return
        
        if choice not in options:
            print("Invalid choice. Please try again.")
            return menu()
        
        option_name, option_key = options[choice]
        target = input("Enter target: ").strip()
        
        if not target:
            print("Target cannot be empty.")
            return menu()
        if not is_in_scope(target):
            print(f"\n[BLOCKED] {target} is outside the allowed scope.")
            print("Halting for safety.")
            return menu()
        
        print(f"\nExecuting {option_name} on {target}...")
        
        if option_key == "orchestrator":
            result = orchestrator(target)
        elif option_key == "recon":
            result = run_recon(target)
        elif option_key == "scope_check":
            result = {"target": target, "in_scope": is_in_scope(target)}
        
        print_result(result)
        
    except ValueError:
        print("Invalid input. Please enter a number.")
        return menu()
    except Exception as e:
        print(f"Error occurred: {e}")
        import traceback
        traceback.print_exc()
        return menu()
    
    # Ask if user wants to continue
    cont = input("\nWould you like to perform another action? (y/n): ").lower()
    if cont == 'y':
        return menu()
    else:
        print("Goodbye!")

if __name__ == "__main__":
    menu()

